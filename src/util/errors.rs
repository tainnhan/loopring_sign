use std::fmt;

#[derive(Debug, Clone)]
pub enum PoseidonError {
    EmptyInputError,
    InputsExceedRate,
}

impl fmt::Display for PoseidonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PoseidonError::EmptyInputError => write!(f, "No inputs provided"),
            PoseidonError::InputsExceedRate => write!(f, "Inputs exceed the rate."),
        }
    }
}

impl std::error::Error for PoseidonError {}
