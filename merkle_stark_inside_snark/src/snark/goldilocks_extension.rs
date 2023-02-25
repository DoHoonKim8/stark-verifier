use std::{
    fmt::{Debug, Display, Formatter, Result},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use halo2_proofs::arithmetic::Field;
use halo2curves::goldilocks::fp::Goldilocks;
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Optimal extension field trait.
/// A degree `d` field extension is optimal if there exists a base field element `W`,
/// such that the extension is `F[X]/(X^d-W)`.
pub trait OEF<const D: usize>: FieldExtension<D> {
    // Element W of BaseField, such that `X^d - W` is irreducible over BaseField.
    const W: Self::BaseField;

    // Element of BaseField such that DTH_ROOT^D == 1. Implementors
    // should set this to W^((p - 1)/D), where W is as above and p is
    // the order of the BaseField.
    const DTH_ROOT: Self::BaseField;
}

pub trait Frobenius<const D: usize>: OEF<D> {
    /// FrobeniusField automorphisms: x -> x^p, where p is the order of BaseField.
    fn frobenius(&self) -> Self {
        self.repeated_frobenius(1)
    }

    /// Repeated Frobenius automorphisms: x -> x^(p^count).
    ///
    /// Follows precomputation suggestion in Section 11.3.3 of the
    /// Handbook of Elliptic and Hyperelliptic Curve Cryptography.
    fn repeated_frobenius(&self, count: usize) -> Self {
        if count == 0 {
            return *self;
        } else if count >= D {
            // x |-> x^(p^D) is the identity, so x^(p^count) ==
            // x^(p^(count % D))
            return self.repeated_frobenius(count % D);
        }
        let arr = self.to_basefield_array();

        // z0 = DTH_ROOT^count = W^(k * count) where k = floor((p^D-1)/D)
        let mut z0 = Self::DTH_ROOT;
        for _ in 1..count {
            z0 *= Self::DTH_ROOT;
        }

        let mut res = [Self::BaseField::zero(); D];
        let mut z = Self::BaseField::one();
        for i in 0..D {
            res[i] = arr[i] * z;
            z *= z0;
        }

        Self::from_basefield_array(res)
    }
}

pub trait Extendable<const D: usize>: Field + Sized {
    type Extension: Field + OEF<D, BaseField = Self> + Frobenius<D> + From<Self>;

    const W: Self;

    const DTH_ROOT: Self;

    /// Chosen so that when raised to the power `(p^D - 1) >> F::Extension::TWO_ADICITY)`
    /// we obtain F::EXT_POWER_OF_TWO_GENERATOR.
    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; D];

    /// Chosen so that when raised to the power `1<<(Self::TWO_ADICITY-Self::BaseField::TWO_ADICITY)`,
    /// we get `Self::BaseField::POWER_OF_TWO_GENERATOR`. This makes `primitive_root_of_unity` coherent
    /// with the base field which implies that the FFT commutes with field inclusion.
    const EXT_POWER_OF_TWO_GENERATOR: [Self; D];
}

pub trait FieldExtension<const D: usize>: Field {
    type BaseField: Field;

    fn to_basefield_array(&self) -> [Self::BaseField; D];

    fn from_basefield_array(arr: [Self::BaseField; D]) -> Self;

    fn from_basefield(x: Self::BaseField) -> Self;

    fn is_in_basefield(&self) -> bool {
        self.to_basefield_array()[1..]
            .iter()
            .all(|x| x.is_zero().into())
    }

    fn scalar_mul(&self, scalar: Self::BaseField) -> Self {
        let mut res = self.to_basefield_array();
        res.iter_mut().for_each(|x| {
            *x *= scalar;
        });
        Self::from_basefield_array(res)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct QuadraticExtension<F: Extendable<2>>(pub [F; 2]);

impl Extendable<2> for Goldilocks {
    type Extension = QuadraticExtension<Self>;

    // Verifiable in Sage with
    // `R.<x> = GF(p)[]; assert (x^2 - 7).is_irreducible()`.
    const W: Self = Self(7);

    // DTH_ROOT = W^((ORDER - 1)/2)
    const DTH_ROOT: Self = Self(18446744069414584320);

    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; 2] =
        [Self(18081566051660590251), Self(16121475356294670766)];

    const EXT_POWER_OF_TWO_GENERATOR: [Self; 2] = [Self(0), Self(15659105665374529263)];
}

impl<F: Extendable<2>> Default for QuadraticExtension<F> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: Extendable<2>> OEF<2> for QuadraticExtension<F> {
    const W: F = F::W;
    const DTH_ROOT: F = F::DTH_ROOT;
}

impl<F: Extendable<2>> Frobenius<2> for QuadraticExtension<F> {}

impl<F: Extendable<2>> FieldExtension<2> for QuadraticExtension<F> {
    type BaseField = F;

    fn to_basefield_array(&self) -> [F; 2] {
        self.0
    }

    fn from_basefield_array(arr: [F; 2]) -> Self {
        Self(arr)
    }

    fn from_basefield(x: F) -> Self {
        x.into()
    }
}

impl<F: Extendable<2>> From<F> for QuadraticExtension<F> {
    fn from(x: F) -> Self {
        Self([x, F::zero()])
    }
}

impl<F: Extendable<2>> Field for QuadraticExtension<F> {
    fn random(mut rng: impl RngCore) -> Self {
        QuadraticExtension([F::random(&mut rng), F::random(&mut rng)])
    }

    fn zero() -> Self {
        QuadraticExtension([F::zero(), F::zero()])
    }

    fn one() -> Self {
        QuadraticExtension([F::one(), F::zero()])
    }

    fn is_zero(&self) -> Choice {
        self.0[0].is_zero() & self.0[1].is_zero()
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn double(&self) -> Self {
        self.double()
    }

    fn sqrt(&self) -> CtOption<Self> {
        unimplemented!()
    }

    fn invert(&self) -> CtOption<Self> {
        if self.is_zero().into() {
            return CtOption::new(Self::zero(), 0.into());
        }

        let a_pow_r_minus_1 = self.frobenius();
        let a_pow_r = a_pow_r_minus_1 * *self;
        debug_assert!(FieldExtension::<2>::is_in_basefield(&a_pow_r));

        CtOption::new(
            FieldExtension::<2>::scalar_mul(&a_pow_r_minus_1, a_pow_r.0[0].invert().unwrap()),
            1.into(),
        )
    }
}

impl<F: Extendable<2>> Display for QuadraticExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:?} + {:?}*a", self.0[0], self.0[1])
    }
}

impl<F: Extendable<2>> Debug for QuadraticExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self, f)
    }
}

impl<F: Extendable<2>> Neg for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self([-self.0[0], -self.0[1]])
    }
}

impl<F: Extendable<2>> Add for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self([self.0[0] + rhs.0[0], self.0[1] + rhs.0[1]])
    }
}

impl<'a, F: Extendable<2>> Add<&'a QuadraticExtension<F>> for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'a QuadraticExtension<F>) -> Self::Output {
        self + *rhs
    }
}

impl<F: Extendable<2>> AddAssign for QuadraticExtension<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'a, F: Extendable<2>> AddAssign<&'a QuadraticExtension<F>> for QuadraticExtension<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &'a QuadraticExtension<F>) {
        *self = *self + *rhs;
    }
}

impl<F: Extendable<2>> Sub for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self([self.0[0] - rhs.0[0], self.0[1] - rhs.0[1]])
    }
}

impl<'a, F: Extendable<2>> Sub<&'a QuadraticExtension<F>> for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'a QuadraticExtension<F>) -> Self::Output {
        self - *rhs
    }
}

impl<F: Extendable<2>> SubAssign for QuadraticExtension<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'a, F: Extendable<2>> SubAssign<&'a QuadraticExtension<F>> for QuadraticExtension<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a QuadraticExtension<F>) {
        *self = *self - *rhs;
    }
}

impl<F: Extendable<2>> Mul for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let Self([a0, a1]) = self;
        let Self([b0, b1]) = rhs;

        let c0 = a0 * b0 + <Self as OEF<2>>::W * a1 * b1;
        let c1 = a0 * b1 + a1 * b0;

        Self([c0, c1])
    }
}

impl<'a, F: Extendable<2>> Mul<&'a QuadraticExtension<F>> for QuadraticExtension<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'a QuadraticExtension<F>) -> Self::Output {
        self * *rhs
    }
}

impl<F: Extendable<2>> MulAssign for QuadraticExtension<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<'a, F: Extendable<2>> MulAssign<&'a QuadraticExtension<F>> for QuadraticExtension<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a QuadraticExtension<F>) {
        *self = *self * *rhs;
    }
}

impl<F: Extendable<2>> ConstantTimeEq for QuadraticExtension<F> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0]) & self.0[1].ct_eq(&other.0[1])
    }
}

impl<F: Extendable<2>> ConditionallySelectable for QuadraticExtension<F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        unimplemented!()
    }
}
