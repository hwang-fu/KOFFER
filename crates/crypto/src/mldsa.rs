  //! ML-DSA lattice-based signature backend, wrapping the RustCrypto `ml-dsa` crate.
  //!
  //! Generic over the parameter set `P`: `MlDsa65` for the showcase profile,
  //! `MlDsa87` for the CNSA 2.0 profile. The scheme is stateless, so it implements
  //! the plain `Signer` rather than the stateful one the hash-based backend needs.
