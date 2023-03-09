use halo2wrong_maingate::MainGateConfig;


pub struct FriVerifierChip {
    main_gate_config: MainGateConfig,
}

impl FriVerifierChip {
    pub fn construct(main_gate_config: &MainGateConfig) -> Self {
        Self {
            main_gate_config: main_gate_config.clone(),
        }
    }
}
