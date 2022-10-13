use super::*;

pub trait OpCode {
    const OP_CODE: u64;
}

impl<R, A> OpCode for And<R, A> {
    const OP_CODE: u64 = 0b00000;
}
impl<R, A> OpCode for Or<R, A> {
    const OP_CODE: u64 = 0b00001;
}
impl<R, A> OpCode for Xor<R, A> {
    const OP_CODE: u64 = 0b00010;
}
impl<R, A> OpCode for Not<R, A> {
    const OP_CODE: u64 = 0b00011;
}
impl<R, A> OpCode for Add<R, A> {
    const OP_CODE: u64 = 0b00100;
}
impl<R, A> OpCode for Sub<R, A> {
    const OP_CODE: u64 = 0b00101;
}
impl<R, A> OpCode for Mull<R, A> {
    const OP_CODE: u64 = 0b00110;
}
impl<R, A> OpCode for UMulh<R, A> {
    const OP_CODE: u64 = 0b00111;
}
impl<R, A> OpCode for SMulh<R, A> {
    const OP_CODE: u64 = 0b01000;
}
impl<R, A> OpCode for UDiv<R, A> {
    const OP_CODE: u64 = 0b01001;
}
impl<R, A> OpCode for UMod<R, A> {
    const OP_CODE: u64 = 0b01010;
}
impl<R, A> OpCode for Shl<R, A> {
    const OP_CODE: u64 = 0b01011;
}
impl<R, A> OpCode for Shr<R, A> {
    const OP_CODE: u64 = 0b01100;
}
impl<R, A> OpCode for Cmpe<R, A> {
    const OP_CODE: u64 = 0b01101;
}
impl<R, A> OpCode for Cmpa<R, A> {
    const OP_CODE: u64 = 0b01110;
}
impl<R, A> OpCode for Cmpae<R, A> {
    const OP_CODE: u64 = 0b01111;
}
impl<R, A> OpCode for Cmpg<R, A> {
    const OP_CODE: u64 = 0b10000;
}
impl<R, A> OpCode for Cmpge<R, A> {
    const OP_CODE: u64 = 0b10001;
}
impl<R, A> OpCode for Mov<R, A> {
    const OP_CODE: u64 = 0b10010;
}
impl<R, A> OpCode for CMov<R, A> {
    const OP_CODE: u64 = 0b10011;
}
impl<A> OpCode for Jmp<A> {
    const OP_CODE: u64 = 0b10100;
}
impl<A> OpCode for CJmp<A> {
    const OP_CODE: u64 = 0b10101;
}
impl<A> OpCode for CnJmp<A> {
    const OP_CODE: u64 = 0b10110;
}
impl<R, A> OpCode for StoreW<R, A> {
    const OP_CODE: u64 = 0b11100;
}
impl<R, A> OpCode for LoadW<R, A> {
    const OP_CODE: u64 = 0b11101;
}
impl<A> OpCode for Answer<A> {
    const OP_CODE: u64 = 0b11111;
}
