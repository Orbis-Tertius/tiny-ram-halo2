use halo2_proofs::{arithmetic::FieldExt, plonk};

use crate::{assign::AssignCell, instructions::*};

pub trait OutPut {
    const OUT: Out<bool>;
}

/// This corresponds to `s_out` in the paper (page 24).
#[derive(Debug, Clone, Copy)]
pub struct Out<T> {
    /// logical
    pub and: T,
    pub xor: T,
    pub or: T,

    /// arithmetic
    pub sum: T,
    pub ssum: T,
    pub prod: T,
    pub sprod: T,
    pub mod_: T,

    pub shift: T,

    pub flag1: T,
    pub flag2: T,
    pub flag3: T,
    pub flag4: T,
}

// serves as default, except it's private.
const EMPTY_OUT: Out<bool> = Out {
    and: false,
    xor: false,
    or: false,
    sum: false,
    prod: false,
    ssum: false,
    sprod: false,
    mod_: false,
    shift: false,
    flag1: false,
    flag2: false,
    flag3: false,
    flag4: false,
};

impl<T> Out<T> {
    pub fn new(mut new_fn: impl FnMut() -> T) -> Out<T> {
        Out {
            and: new_fn(),
            xor: new_fn(),
            or: new_fn(),
            sum: new_fn(),
            prod: new_fn(),
            ssum: new_fn(),
            sprod: new_fn(),
            mod_: new_fn(),
            shift: new_fn(),
            flag1: new_fn(),
            flag2: new_fn(),
            flag3: new_fn(),
            flag4: new_fn(),
        }
    }

    pub fn map<B>(self, mut f: impl FnMut(T) -> B) -> Out<B> {
        Out {
            and: f(self.and),
            xor: f(self.xor),
            or: f(self.or),
            sum: f(self.sum),
            prod: f(self.prod),
            ssum: f(self.ssum),
            sprod: f(self.sprod),
            mod_: f(self.mod_),
            shift: f(self.shift),
            flag1: f(self.flag1),
            flag2: f(self.flag2),
            flag3: f(self.flag3),
            flag4: f(self.flag4),
        }
    }
}

impl<C> Out<C> {
    pub fn push_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        offset: usize,
        vals: Out<bool>,
    ) -> Result<(), plonk::Error> {
        let Self {
            and,
            xor,
            or,
            sum,
            prod,
            ssum,
            sprod,
            mod_,
            shift,
            flag1,
            flag2,
            flag3,
            flag4,
        } = self;

        region.assign_cell(and, offset, vals.and.into())?;
        region.assign_cell(xor, offset, vals.xor.into())?;
        region.assign_cell(or, offset, vals.or.into())?;
        region.assign_cell(sum, offset, vals.sum.into())?;
        region.assign_cell(prod, offset, vals.prod.into())?;
        region.assign_cell(ssum, offset, vals.ssum.into())?;
        region.assign_cell(sprod, offset, vals.sprod.into())?;
        region.assign_cell(mod_, offset, vals.mod_.into())?;
        region.assign_cell(shift, offset, vals.shift.into())?;
        region.assign_cell(flag1, offset, vals.flag1.into())?;
        region.assign_cell(flag2, offset, vals.flag2.into())?;
        region.assign_cell(flag3, offset, vals.flag3.into())?;
        region.assign_cell(flag4, offset, vals.flag4.into())?;

        Ok(())
    }
}

impl<T> Out<T> {
    pub fn convert<B: From<T>>(self) -> Out<B> {
        Out {
            and: self.and.into(),
            xor: self.xor.into(),
            or: self.or.into(),
            sum: self.sum.into(),
            prod: self.prod.into(),
            ssum: self.ssum.into(),
            sprod: self.sprod.into(),
            mod_: self.mod_.into(),
            shift: self.shift.into(),
            flag1: self.flag1.into(),
            flag2: self.flag2.into(),
            flag3: self.flag3.into(),
            flag4: self.flag4.into(),
        }
    }
}

impl<R, A> OutPut for And<R, A> {
    const OUT: Out<bool> = Out {
        and: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Or<R, A> {
    const OUT: Out<bool> = Out {
        or: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Xor<R, A> {
    const OUT: Out<bool> = Out {
        xor: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Not<R, A> {
    const OUT: Out<bool> = Out {
        xor: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Add<R, A> {
    const OUT: Out<bool> = Out {
        sum: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Sub<R, A> {
    const OUT: Out<bool> = Out {
        sum: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Mull<R, A> {
    const OUT: Out<bool> = Out {
        prod: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for UMulh<R, A> {
    const OUT: Out<bool> = Out {
        prod: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for SMulh<R, A> {
    const OUT: Out<bool> = Out {
        sprod: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for UDiv<R, A> {
    const OUT: Out<bool> = Out {
        mod_: true,
        flag1: true,
        flag2: true,
        flag3: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for UMod<R, A> {
    const OUT: Out<bool> = Out {
        mod_: true,
        flag1: true,
        flag2: true,
        flag3: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Shl<R, A> {
    const OUT: Out<bool> = Out {
        shift: true,
        flag4: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Shr<R, A> {
    const OUT: Out<bool> = Out {
        shift: true,
        flag4: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Cmpe<R, A> {
    const OUT: Out<bool> = Out {
        xor: true,
        flag1: true,
        flag2: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Cmpa<R, A> {
    const OUT: Out<bool> = Out {
        sum: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Cmpae<R, A> {
    const OUT: Out<bool> = Out {
        sum: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Cmpg<R, A> {
    const OUT: Out<bool> = Out {
        ssum: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Cmpge<R, A> {
    const OUT: Out<bool> = Out {
        ssum: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for Mov<R, A> {
    const OUT: Out<bool> = Out {
        xor: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for CMov<R, A> {
    const OUT: Out<bool> = Out {
        mod_: true,
        ..EMPTY_OUT
    };
}

impl<A> OutPut for Jmp<A> {
    const OUT: Out<bool> = Out {
        xor: true,
        ..EMPTY_OUT
    };
}

impl<A> OutPut for CJmp<A> {
    const OUT: Out<bool> = Out {
        mod_: true,
        ..EMPTY_OUT
    };
}

impl<A> OutPut for CnJmp<A> {
    const OUT: Out<bool> = Out {
        mod_: true,
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for LoadW<R, A> {
    const OUT: Out<bool> = Out {
        // FIXME
        ..EMPTY_OUT
    };
}

impl<R, A> OutPut for StoreW<R, A> {
    const OUT: Out<bool> = Out {
        xor: true,
        ..EMPTY_OUT
    };
}

impl<A> OutPut for Answer<A> {
    const OUT: Out<bool> = EMPTY_OUT;
}
