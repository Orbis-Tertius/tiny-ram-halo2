use halo2_proofs::{arithmetic::FieldExt, plonk};

use crate::{assign::PushRow, instructions::*};

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
}

impl<C> Out<C> {
    pub fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
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

        region.push_cell(and, vals.and.into())?;
        region.push_cell(xor, vals.xor.into())?;
        region.push_cell(or, vals.or.into())?;
        region.push_cell(sum, vals.sum.into())?;
        region.push_cell(prod, vals.prod.into())?;
        region.push_cell(ssum, vals.ssum.into())?;
        region.push_cell(sprod, vals.sprod.into())?;
        region.push_cell(mod_, vals.mod_.into())?;
        region.push_cell(shift, vals.shift.into())?;
        region.push_cell(flag1, vals.flag1.into())?;
        region.push_cell(flag2, vals.flag2.into())?;
        region.push_cell(flag3, vals.flag3.into())?;
        region.push_cell(flag4, vals.flag4.into())?;

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
