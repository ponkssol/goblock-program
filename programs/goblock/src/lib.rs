#![no_std]

use core::mem::MaybeUninit;
use pinocchio::{
    cpi::{invoke_signed_with_bounds, invoke_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    no_allocator, nostd_panic_handler, program_entrypoint,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use solana_program_log::log;

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

#[used]
static SECURITY_TXT: &str = "\
=======BEGIN SECURITY.TXT V1=======
name: goblock
project_url: https://github.com/ponkssol/goblock-dex
contacts: link:https://github.com/ponkssol/goblock-program
policy: https://github.com/ponkssol/goblock-program
preferred_languages: en
source_code: https://github.com/ponkssol/goblock-program
logo: https://raw.githubusercontent.com/ponkssol/goblock-program/main/logo.png
=======END SECURITY.TXT V1=======
";

const CHECKED: u8 = 1;
const MAX_INNER: usize = 16;
const MAX_ACCOUNTS: usize = 32;
const BELOW_FLOOR: u32 = 1;
const FEE_REJECTED: u32 = 2;
const FEE_CAP: u64 = 2_000_000_000;

const DISTRIBUTE: u8 = 2;
const SET_MINT: u8 = 3;
const NOTHING_TO_DO: u32 = 3;
const BUYBACK_REJECTED: u32 = 4;
const MINT_LOCKED: u32 = 5;
const NOT_ADMIN: u32 = 6;
const OVERSPENT: u32 = 7;
const BELOW_BURN_FLOOR: u32 = 8;

/// New vault revenue is split once it reaches 0.1 SOL.
const THRESHOLD: u64 = 100_000_000;
const TEAM_PERCENT: u64 = 60;
/// Kept in the vault so the account stays rent exempt.
const VAULT_RESERVE: u64 = 1_000_000;
const VAULT_SEED: &[u8] = b"vault";
const VAULT_BUMP: u8 = 254;
const CONFIG_SEED: &[u8] = b"config";
const CONFIG_BUMP: u8 = 255;
const CONFIG_LEN: usize = 80;
const CONFIG_VERSION: u8 = 1;
const MINT_AT: usize = 8;
const RESERVED_AT: usize = 40;
const TEAM_TOTAL_AT: usize = 48;
const SPENT_TOTAL_AT: usize = 56;
const BURNED_TOTAL_AT: usize = 64;
const ROUNDS_AT: usize = 72;

const BUY: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];
const BUY_EXACT_SOL_IN: [u8; 8] = [56, 252, 116, 8, 158, 223, 205, 95];
const BUY_EXACT_QUOTE_IN: [u8; 8] = [198, 46, 21, 82, 180, 217, 232, 112];

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    core::hint::black_box(SECURITY_TXT);
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let tag = data.first().copied().ok_or(ProgramError::InvalidInstructionData)?;
    log("goblock:");
    if tag == DISTRIBUTE {
        return distribute(program_id, accounts, data);
    }
    if tag == SET_MINT {
        return set_mint(program_id, accounts, data);
    }
    if tag != CHECKED {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut cursor = 1;

    let output_index = read_u8(data, &mut cursor)? as usize;
    let min_out = read_u64(data, &mut cursor)?;
    let mint = read_pubkey(data, &mut cursor)?;
    let fee = read_u64(data, &mut cursor)?;
    let treasury_fee = read_u64(data, &mut cursor)?;
    let system_index = read_u8(data, &mut cursor)? as usize;
    let treasury_index = read_u8(data, &mut cursor)? as usize;
    let brand_index = read_u8(data, &mut cursor)? as usize;
    if output_index == 0 || !accounts.get(output_index).is_some_and(|account| account.is_writable()) {
        return Err(ProgramError::InvalidAccountData);
    }
    let before = token_amount(&accounts[output_index])?;
    let pre_count = read_u8(data, &mut cursor)? as usize;
    let post_count = read_u8(data, &mut cursor)? as usize;
    if pre_count.saturating_add(post_count) == 0 || pre_count.saturating_add(post_count) > MAX_INNER {
        return Err(ProgramError::InvalidInstructionData);
    }
    for _ in 0..pre_count {
        forward(program_id, accounts, data, &mut cursor)?;
    }
    let output = &accounts[output_index];
    let (found_mint, owner, after) = token_fields(output)?;
    if found_mint != mint || owner != *signer.address().as_array() {
        return Err(ProgramError::InvalidAccountData);
    }
    let need = before.checked_add(min_out).ok_or(ProgramError::InvalidInstructionData)?;
    if after < need {
        return Err(ProgramError::Custom(BELOW_FLOOR));
    }
    for _ in 0..post_count {
        forward(program_id, accounts, data, &mut cursor)?;
    }
    take_fee(accounts, fee, treasury_fee, system_index, treasury_index, brand_index)?;
    if cursor != data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

fn take_fee(
    accounts: &[AccountView],
    fee: u64,
    treasury_fee: u64,
    system_index: usize,
    treasury_index: usize,
    brand_index: usize,
) -> ProgramResult {
    if fee == 0 {
        return Ok(());
    }
    if fee > FEE_CAP || treasury_fee > fee {
        return Err(ProgramError::Custom(FEE_REJECTED));
    }
    let system = accounts.get(system_index).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if system.address().as_array() != &[0; 32] {
        return Err(ProgramError::IncorrectProgramId);
    }
    let treasury = accounts.get(treasury_index).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let brand = accounts.get(brand_index).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !treasury.is_writable() || !brand.is_writable() || treasury_index == 0 || brand_index == 0 {
        return Err(ProgramError::Custom(FEE_REJECTED));
    }
    let payer = &accounts[0];
    if treasury_index == brand_index {
        if treasury_fee != fee {
            return Err(ProgramError::Custom(FEE_REJECTED));
        }
        return transfer(payer, treasury, fee, system);
    }
    if treasury_fee > 0 {
        transfer(payer, treasury, treasury_fee, system)?;
    }
    let brand_fee = fee - treasury_fee;
    if brand_fee > 0 {
        transfer(payer, brand, brand_fee, system)?;
    }
    Ok(())
}

fn transfer(from: &AccountView, to: &AccountView, lamports: u64, system: &AccountView) -> ProgramResult {
    let mut data = [0; 12];
    data[0] = 2;
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    let metas = [
        InstructionAccount::new(from.address(), true, true),
        InstructionAccount::new(to.address(), true, false),
    ];
    let instruction = InstructionView {
        program_id: system.address(),
        data: &data,
        accounts: &metas,
    };
    invoke_with_bounds::<2, _>(&instruction, &[from, to])
}

/// Accounts: payer, vault, config, team, system program, vault token account, mint, token program,
/// then the accounts of the buyback instructions.
///
/// New vault revenue of at least `THRESHOLD` pays `TEAM_PERCENT` to the team and reserves the rest for
/// the buyback. The buyback may only buy the configured mint into the vault, and every token bought is
/// burned. Reserved lamports can never reach the team.
#[inline(never)]
fn distribute(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let payer = &accounts[0];
    let vault = &accounts[1];
    let config = &accounts[2];
    let team = &accounts[3];
    let system = &accounts[4];
    if vault.address().as_array() != &VAULT
        || config.address().as_array() != &CONFIG
        || team.address().as_array() != &TEAM
        || system.address().as_array() != &[0; 32]
        || !vault.is_writable()
        || !config.is_writable()
        || !team.is_writable()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut cursor = 1;
    let min_burn = read_u64(data, &mut cursor)?;
    let steps = read_u8(data, &mut cursor)? as usize;
    if steps > MAX_INNER {
        return Err(ProgramError::InvalidInstructionData);
    }

    ensure_config(program_id, payer, config, system)?;
    let mut state = [0u8; CONFIG_LEN];
    {
        let stored = config.try_borrow()?;
        state.copy_from_slice(&stored[..CONFIG_LEN]);
    }
    let mut reserved = get_u64(&state, RESERVED_AT);
    let mut done = false;

    let free = vault.lamports().saturating_sub(VAULT_RESERVE).saturating_sub(reserved);
    if free >= THRESHOLD {
        let to_team = free / 100 * TEAM_PERCENT + free % 100 * TEAM_PERCENT / 100;
        transfer_from_vault(vault, team, to_team, system)?;
        reserved += free - to_team;
        add_u64(&mut state, TEAM_TOTAL_AT, to_team);
        add_u64(&mut state, ROUNDS_AT, 1);
        done = true;
    }

    if steps > 0 {
        let holding = &accounts[5];
        let mint = &accounts[6];
        let token_program = &accounts[7];
        let stored_mint = &state[MINT_AT..MINT_AT + 32];
        if stored_mint == [0; 32]
            || mint.address().as_array() != stored_mint
            || !mint.is_writable()
            || !holding.is_writable()
            || !is_token_program(token_program.address().as_array())
        {
            return Err(ProgramError::Custom(BUYBACK_REJECTED));
        }
        let before = vault.lamports();
        for _ in 0..steps {
            forward_buyback(program_id, accounts, data, &mut cursor, holding.address(), mint.address())?;
        }
        let after = vault.lamports();
        if after >= before {
            reserved += after - before;
        } else {
            let spent = before - after;
            if spent > reserved {
                return Err(ProgramError::Custom(OVERSPENT));
            }
            reserved -= spent;
            add_u64(&mut state, SPENT_TOTAL_AT, spent);
        }
        let burned = burn_holding(vault, holding, mint, token_program)?;
        if burned < min_burn {
            return Err(ProgramError::Custom(BELOW_BURN_FLOOR));
        }
        add_u64(&mut state, BURNED_TOTAL_AT, burned);
        done = true;
    }

    if cursor != data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !done {
        return Err(ProgramError::Custom(NOTHING_TO_DO));
    }
    put_u64(&mut state, RESERVED_AT, reserved);
    let mut config = *config;
    config.try_borrow_mut()?[..CONFIG_LEN].copy_from_slice(&state);
    Ok(())
}

/// Accounts: team wallet, config, system program, mint. The mint can be set once.
#[inline(never)]
fn set_mint(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if data.len() != 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let admin = &accounts[0];
    let config = &accounts[1];
    let system = &accounts[2];
    let mint = &accounts[3];
    if admin.address().as_array() != &TEAM {
        return Err(ProgramError::Custom(NOT_ADMIN));
    }
    if config.address().as_array() != &CONFIG || !config.is_writable() || system.address().as_array() != &[0; 32] {
        return Err(ProgramError::InvalidAccountData);
    }
    if !is_token_program(mint.owner().as_array()) || mint.data_len() < 82 || mint.try_borrow()?[45] != 1 {
        return Err(ProgramError::InvalidAccountData);
    }
    ensure_config(program_id, admin, config, system)?;
    let mut config = *config;
    let mut stored = config.try_borrow_mut()?;
    if stored[MINT_AT..MINT_AT + 32] != [0; 32] {
        return Err(ProgramError::Custom(MINT_LOCKED));
    }
    stored[MINT_AT..MINT_AT + 32].copy_from_slice(mint.address().as_array());
    Ok(())
}

#[inline(never)]
fn ensure_config(program_id: &Address, payer: &AccountView, config: &AccountView, system: &AccountView) -> ProgramResult {
    if config.owned_by(program_id) {
        return if config.data_len() >= CONFIG_LEN { Ok(()) } else { Err(ProgramError::InvalidAccountData) };
    }
    if config.owner().as_array() != &[0; 32] || config.data_len() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    let need = Rent::get()?.try_minimum_balance(CONFIG_LEN)?;
    if config.lamports() < need {
        transfer(payer, config, need - config.lamports(), system)?;
    }
    let bump = [CONFIG_BUMP];
    let seeds = [Seed::from(CONFIG_SEED), Seed::from(&bump)];
    let signer = [Signer::from(&seeds)];
    let metas = [InstructionAccount::new(config.address(), true, true)];

    let mut allocate = [0u8; 12];
    allocate[0] = 8;
    allocate[4..12].copy_from_slice(&(CONFIG_LEN as u64).to_le_bytes());
    let instruction = InstructionView { program_id: system.address(), data: &allocate, accounts: &metas };
    invoke_signed_with_bounds::<1, _>(&instruction, &[config], &signer)?;

    let mut assign = [0u8; 36];
    assign[0] = 1;
    assign[4..36].copy_from_slice(program_id.as_array());
    let instruction = InstructionView { program_id: system.address(), data: &assign, accounts: &metas };
    invoke_signed_with_bounds::<1, _>(&instruction, &[config], &signer)?;

    let mut config = *config;
    config.try_borrow_mut()?[0] = CONFIG_VERSION;
    Ok(())
}

#[inline(never)]
fn transfer_from_vault(vault: &AccountView, to: &AccountView, lamports: u64, system: &AccountView) -> ProgramResult {
    let mut data = [0; 12];
    data[0] = 2;
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    let metas = [
        InstructionAccount::new(vault.address(), true, true),
        InstructionAccount::new(to.address(), true, false),
    ];
    let instruction = InstructionView { program_id: system.address(), data: &data, accounts: &metas };
    let bump = [VAULT_BUMP];
    let seeds = [Seed::from(VAULT_SEED), Seed::from(&bump)];
    invoke_signed_with_bounds::<2, _>(&instruction, &[vault, to], &[Signer::from(&seeds)])
}

#[inline(never)]
fn forward_buyback(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
    cursor: &mut usize,
    holding: &Address,
    mint: &Address,
) -> ProgramResult {
    let program_index = read_u8(data, cursor)? as usize;
    let program = accounts.get(program_index).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if program.address() == program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let account_count = read_u8(data, cursor)? as usize;
    if account_count > MAX_ACCOUNTS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut raw_metas: [MaybeUninit<InstructionAccount>; MAX_ACCOUNTS] = [const { MaybeUninit::uninit() }; MAX_ACCOUNTS];
    let mut views = [accounts[0]; MAX_ACCOUNTS];
    for slot in 0..account_count {
        let index = read_u8(data, cursor)? as usize;
        let account = accounts.get(index).ok_or(ProgramError::NotEnoughAccountKeys)?;
        let signs = account.is_signer() || account.address().as_array() == &VAULT;
        raw_metas[slot].write(InstructionAccount::new(account.address(), account.is_writable(), signs));
        views[slot] = *account;
    }
    let metas = unsafe { core::slice::from_raw_parts(raw_metas.as_ptr() as *const InstructionAccount, account_count) };

    let data_len = read_u16(data, cursor)? as usize;
    let instruction_data = data.get(*cursor..*cursor + data_len).ok_or(ProgramError::InvalidInstructionData)?;
    *cursor += data_len;
    check_buyback(program.address().as_array(), &views[..account_count], instruction_data, holding, mint)?;

    let instruction = InstructionView {
        program_id: program.address(),
        data: instruction_data,
        accounts: metas,
    };
    let bump = [VAULT_BUMP];
    let seeds = [Seed::from(VAULT_SEED), Seed::from(&bump)];
    invoke_signed_with_bounds::<MAX_ACCOUNTS, _>(&instruction, &views[..account_count], &[Signer::from(&seeds)])
}

/// The vault signs these, so each one is limited to what a buyback needs.
#[inline(never)]
fn check_buyback(program: &[u8; 32], views: &[AccountView], data: &[u8], holding: &Address, mint: &Address) -> ProgramResult {
    let key = |index: usize| views.get(index).map(|account| account.address().as_array());
    let head = data.get(..8);
    let allowed = if program == &PUMP {
        (head == Some(&BUY[..]) || head == Some(&BUY_EXACT_SOL_IN[..]))
            && key(2) == Some(mint.as_array())
            && key(5) == Some(holding.as_array())
            && key(6) == Some(&VAULT)
    } else if program == &PUMP_AMM {
        (head == Some(&BUY[..]) || head == Some(&BUY_EXACT_QUOTE_IN[..]))
            && key(1) == Some(&VAULT)
            && key(3) == Some(mint.as_array())
            && key(5) == Some(holding.as_array())
    } else if program == &ASSOCIATED_TOKEN {
        matches!(data.first(), None | Some(0) | Some(1)) && key(2) == Some(&VAULT)
    } else if program == &[0; 32] {
        data.len() == 12 && data[..4] == [2, 0, 0, 0] && views.get(1).is_some_and(vault_token_account)
    } else if is_token_program(program) {
        match data.first() {
            Some(17) => true,
            Some(9) => key(1) == Some(&VAULT),
            _ => false,
        }
    } else {
        false
    };
    if allowed {
        Ok(())
    } else {
        Err(ProgramError::Custom(BUYBACK_REJECTED))
    }
}

fn vault_token_account(account: &AccountView) -> bool {
    if !is_token_program(account.owner().as_array()) || account.data_len() < 165 {
        return false;
    }
    match account.try_borrow() {
        Ok(data) => data[32..64] == VAULT,
        Err(_) => false,
    }
}

#[inline(never)]
fn burn_holding(
    vault: &AccountView,
    holding: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
) -> Result<u64, ProgramError> {
    if holding.data_len() == 0 {
        return Ok(0);
    }
    if !holding.owned_by(token_program.address()) || !mint.owned_by(token_program.address()) {
        return Err(ProgramError::Custom(BUYBACK_REJECTED));
    }
    let (found_mint, owner, amount) = token_fields(holding)?;
    if found_mint != *mint.address().as_array() || owner != VAULT {
        return Err(ProgramError::Custom(BUYBACK_REJECTED));
    }
    if amount == 0 {
        return Ok(0);
    }
    let mut data = [0; 9];
    data[0] = 8;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    let metas = [
        InstructionAccount::new(holding.address(), true, false),
        InstructionAccount::new(mint.address(), true, false),
        InstructionAccount::new(vault.address(), false, true),
    ];
    let instruction = InstructionView { program_id: token_program.address(), data: &data, accounts: &metas };
    let bump = [VAULT_BUMP];
    let seeds = [Seed::from(VAULT_SEED), Seed::from(&bump)];
    invoke_signed_with_bounds::<3, _>(&instruction, &[holding, mint, vault], &[Signer::from(&seeds)])?;
    Ok(amount)
}

fn is_token_program(address: &[u8; 32]) -> bool {
    address == &TOKEN || address == &TOKEN_2022
}

fn get_u64(state: &[u8; CONFIG_LEN], at: usize) -> u64 {
    let mut raw = [0; 8];
    raw.copy_from_slice(&state[at..at + 8]);
    u64::from_le_bytes(raw)
}

fn put_u64(state: &mut [u8; CONFIG_LEN], at: usize, value: u64) {
    state[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn add_u64(state: &mut [u8; CONFIG_LEN], at: usize, value: u64) {
    put_u64(state, at, get_u64(state, at).saturating_add(value));
}

fn token_fields(account: &AccountView) -> Result<([u8; 32], [u8; 32], u64), ProgramError> {
    let data = account.try_borrow()?;
    if data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut mint = [0; 32];
    let mut owner = [0; 32];
    mint.copy_from_slice(&data[0..32]);
    owner.copy_from_slice(&data[32..64]);
    let mut amount = [0; 8];
    amount.copy_from_slice(&data[64..72]);
    Ok((mint, owner, u64::from_le_bytes(amount)))
}

fn token_amount(account: &AccountView) -> Result<u64, ProgramError> {
    let data = account.try_borrow()?;
    if data.len() < 72 {
        return Ok(0);
    }
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&data[64..72]);
    Ok(u64::from_le_bytes(bytes))
}

fn read_pubkey(data: &[u8], cursor: &mut usize) -> Result<[u8; 32], ProgramError> {
    let bytes = data.get(*cursor..*cursor + 32).ok_or(ProgramError::InvalidInstructionData)?;
    *cursor += 32;
    let mut raw = [0; 32];
    raw.copy_from_slice(bytes);
    Ok(raw)
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64, ProgramError> {
    let bytes = data.get(*cursor..*cursor + 8).ok_or(ProgramError::InvalidInstructionData)?;
    *cursor += 8;
    let mut raw = [0; 8];
    raw.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(raw))
}

fn forward(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
    cursor: &mut usize,
) -> ProgramResult {
    let program_index = read_u8(data, cursor)? as usize;
    let program = accounts.get(program_index).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if program.address() == program_id || !allowed(program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let account_count = read_u8(data, cursor)? as usize;
    if account_count > MAX_ACCOUNTS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut raw_metas: [MaybeUninit<InstructionAccount>; MAX_ACCOUNTS] = [const { MaybeUninit::uninit() }; MAX_ACCOUNTS];
    let mut views = [accounts[0]; MAX_ACCOUNTS];
    for slot in 0..account_count {
        let index = read_u8(data, cursor)? as usize;
        let account = accounts.get(index).ok_or(ProgramError::NotEnoughAccountKeys)?;
        raw_metas[slot].write(InstructionAccount::new(
            account.address(),
            account.is_writable(),
            account.is_signer(),
        ));
        views[slot] = *account;
    }
    let metas = unsafe { core::slice::from_raw_parts(raw_metas.as_ptr() as *const InstructionAccount, account_count) };

    let data_len = read_u16(data, cursor)? as usize;
    let instruction_data = data.get(*cursor..*cursor + data_len).ok_or(ProgramError::InvalidInstructionData)?;
    *cursor += data_len;

    let instruction = InstructionView {
        program_id: program.address(),
        data: instruction_data,
        accounts: &metas,
    };
    invoke_with_bounds::<MAX_ACCOUNTS, _>(&instruction, &views[..account_count])
}

fn allowed(address: &Address) -> bool {
    ALLOWED.iter().any(|item| item == address.as_array())
}

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, ProgramError> {
    let byte = data.get(*cursor).copied().ok_or(ProgramError::InvalidInstructionData)?;
    *cursor += 1;
    Ok(byte)
}

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16, ProgramError> {
    let bytes = data.get(*cursor..*cursor + 2).ok_or(ProgramError::InvalidInstructionData)?;
    *cursor += 2;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

const ALLOWED: [[u8; 32]; 16] = [
    [0; 32],
    TOKEN,
    TOKEN_2022,
    ASSOCIATED_TOKEN,
    MEMO,
    PUMP,
    PUMP_AMM,
    RAYDIUM_V4,
    RAYDIUM_CLMM,
    RAYDIUM_CPMM,
    RAYDIUM_LAUNCHLAB,
    METEORA_DLMM,
    METEORA_DAMM_V1,
    METEORA_DAMM_V2,
    METEORA_DBC,
    ORCA_WHIRLPOOL,
];

const VAULT: [u8; 32] = [
    98, 15, 251, 211, 180, 138, 202, 122, 242, 240, 246, 109, 216, 246, 180, 154, 113, 250, 228, 167, 103, 127, 217,
    141, 59, 13, 86, 51, 76, 136, 184, 80,
];
const CONFIG: [u8; 32] = [
    68, 74, 175, 160, 28, 208, 23, 233, 117, 230, 86, 48, 199, 83, 129, 29, 221, 168, 184, 91, 8, 26, 118, 8, 140, 75,
    219, 136, 70, 240, 0, 5,
];
/// Receives the team share and sets the buyback mint.
const TEAM: [u8; 32] = [
    177, 101, 208, 149, 22, 110, 148, 154, 183, 135, 236, 121, 17, 111, 135, 51, 192, 16, 57, 240, 61, 203, 181, 168,
    213, 1, 104, 61, 191, 234, 116, 106,
];
const TOKEN: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58,
    140, 245, 133, 126, 255, 0, 169,
];
const TOKEN_2022: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77, 131, 185, 13, 39, 254,
    189, 249, 40, 216, 161, 139, 252,
];
const ASSOCIATED_TOKEN: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218, 255, 16, 132, 4, 142,
    123, 216, 219, 233, 248, 89,
];
const MEMO: [u8; 32] = [
    5, 74, 83, 90, 153, 41, 33, 6, 77, 36, 232, 113, 96, 218, 56, 124, 124, 53, 181, 221, 188, 146, 187, 129, 228, 31,
    168, 64, 65, 5, 68, 141,
];
const PUMP: [u8; 32] = [
    1, 86, 224, 246, 147, 102, 90, 207, 68, 219, 21, 104, 191, 23, 91, 170, 81, 137, 203, 151, 245, 210, 255, 59, 101,
    93, 43, 182, 253, 109, 24, 176,
];
const PUMP_AMM: [u8; 32] = [
    12, 20, 222, 252, 130, 94, 198, 118, 148, 37, 8, 24, 187, 101, 64, 101, 244, 41, 141, 49, 86, 213, 113, 180, 212,
    248, 9, 12, 24, 233, 168, 99,
];
const RAYDIUM_V4: [u8; 32] = [
    75, 217, 73, 196, 54, 2, 195, 63, 32, 119, 144, 237, 22, 163, 82, 76, 161, 185, 151, 92, 241, 33, 162, 169, 12, 255,
    236, 125, 248, 182, 138, 205,
];
const RAYDIUM_CLMM: [u8; 32] = [
    165, 213, 202, 158, 4, 207, 93, 181, 144, 183, 20, 186, 47, 227, 44, 177, 89, 19, 63, 193, 193, 146, 183, 34, 87,
    253, 7, 211, 156, 176, 64, 30,
];
const RAYDIUM_CPMM: [u8; 32] = [
    169, 42, 90, 139, 79, 41, 89, 82, 132, 37, 80, 170, 147, 253, 91, 149, 181, 172, 230, 168, 235, 146, 12, 147, 148, 46,
    67, 105, 12, 32, 236, 115,
];
const METEORA_DLMM: [u8; 32] = [
    4, 233, 225, 47, 188, 132, 232, 38, 201, 50, 204, 233, 226, 100, 12, 206, 21, 89, 12, 28, 98, 115, 176, 146, 87, 8,
    186, 59, 133, 32, 176, 188,
];
const ORCA_WHIRLPOOL: [u8; 32] = [
    14, 3, 104, 95, 142, 144, 144, 83, 228, 88, 18, 28, 102, 245, 167, 106, 237, 199, 112, 106, 161, 28, 130, 248, 170,
    149, 42, 143, 43, 120, 121, 169,
];
const RAYDIUM_LAUNCHLAB: [u8; 32] = [
    5, 4, 59, 149, 77, 202, 38, 225, 239, 145, 181, 44, 79, 143, 137, 175, 138, 111, 90, 200, 198, 33, 86, 241, 113,
    207, 15, 33, 172, 81, 201, 34,
];
const METEORA_DAMM_V1: [u8; 32] = [
    204, 248, 2, 212, 204, 204, 132, 215, 251, 33, 181, 247, 59, 73, 216, 26, 22, 197, 180, 200, 142, 227, 35, 148,
    225, 201, 29, 53, 136, 204, 64, 128,
];
const METEORA_DAMM_V2: [u8; 32] = [
    9, 45, 33, 53, 101, 122, 21, 156, 43, 135, 212, 182, 106, 112, 219, 142, 151, 82, 56, 159, 247, 106, 175, 32, 108,
    237, 6, 58, 56, 249, 90, 237,
];
const METEORA_DBC: [u8; 32] = [
    9, 96, 12, 165, 36, 247, 177, 183, 214, 204, 177, 195, 151, 58, 160, 51, 13, 25, 3, 218, 96, 28, 201, 181, 222,
    227, 198, 98, 180, 202, 209, 73,
];
