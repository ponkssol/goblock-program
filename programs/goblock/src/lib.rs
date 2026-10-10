#![no_std]

use core::mem::MaybeUninit;
use pinocchio::{
    cpi::invoke_with_bounds,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    no_allocator, nostd_panic_handler, program_entrypoint, AccountView, Address, ProgramResult,
};
use solana_program_log::log;

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

const ROUTE: u8 = 0;
const MAX_INNER: usize = 16;
const MAX_ACCOUNTS: usize = 22;

/// `route` forwards whitelisted instructions and logs `goblock:`.
///
/// Data layout, little-endian:
/// `u8 tag` (0), `u8 inner_count`, then for each inner instruction:
/// `u8 program_index`, `u8 account_count`, `u8` account indexes,
/// `u16 data_len`, instruction bytes.
/// Account 0 is the signer. Every program id and account used by an inner
/// instruction is included in this instruction's account list.
fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let signer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if data.first() != Some(&ROUTE) {
        return Err(ProgramError::InvalidInstructionData);
    }

    log("goblock:");
    let mut cursor = 1;
    let inner_count = read_u8(data, &mut cursor)? as usize;
    if inner_count > MAX_INNER {
        return Err(ProgramError::InvalidInstructionData);
    }
    for _ in 0..inner_count {
        forward(program_id, accounts, data, &mut cursor)?;
    }
    if cursor != data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
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

const ALLOWED: [[u8; 32]; 12] = [
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
    METEORA_DLMM,
    ORCA_WHIRLPOOL,
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
