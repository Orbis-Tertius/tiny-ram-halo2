use halo2_proofs::plonk::TableColumn;

use super::out::Out;

pub struct OutTable {
    opcode: TableColumn,
    out: Out<TableColumn>,
}
