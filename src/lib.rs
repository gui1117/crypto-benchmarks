#[cfg(test)]
mod tests {
    use verifiable::ring::ark_vrf;
    use ark_vrf::ring::SrsLookup;
    use ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2;
    use verifiable::ring::{
        bandersnatch::BandersnatchVrfVerifiable, ring_verifier_builder_params, RingDomainSize,
        StaticChunk,
    };
    use verifiable::{Error, GenerateVerifiable};

    type Suite = BandersnatchSha512Ell2;
    type BuilderParams = ark_vrf::ring::RingBuilderPcsParams<Suite>;
    type VerifiableImpl = BandersnatchVrfVerifiable;
    type Intermediate = <VerifiableImpl as GenerateVerifiable>::Intermediate;
    type Member = <VerifiableImpl as GenerateVerifiable>::Member;
    type Config = <VerifiableImpl as GenerateVerifiable>::Config;

    fn entropy_from_index(idx: usize) -> [u8; 32] {
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&(idx as u32).to_le_bytes());
        entropy
    }

    fn member_at(idx: usize) -> Member {
        let secret = VerifiableImpl::new_secret(entropy_from_index(idx));
        VerifiableImpl::member_from_secret(&secret)
    }

    fn push_with_lookup(
        intermediate: &mut Intermediate,
        members: impl Iterator<Item = Member>,
        params: &BuilderParams,
    ) -> Result<(), Error> {
        VerifiableImpl::push_members(intermediate, members, |range| {
            params
                .lookup(range)
                .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                .ok_or(())
        })
    }

    #[test]
    fn ring_size_is_the_push_limit_domain11() {
        test_push_limit(RingDomainSize::Domain11);
    }

    fn test_push_limit(domain: RingDomainSize) {
        let config: Config = domain;
        let ring_size = domain.max_ring_size::<Suite>();
        let builder_params =
            ring_verifier_builder_params::<Suite>(domain);

        let mut builder = VerifiableImpl::start_members(config);
        for idx in 0..ring_size {
            let result =
                push_with_lookup(&mut builder, std::iter::once(member_at(idx)), &builder_params);
            assert!(
                result.is_ok(),
                "failed while pushing member {idx} before reaching the expected ring size limit {ring_size}"
            );
        }

        let overflow =
            push_with_lookup(&mut builder, std::iter::once(member_at(ring_size)), &builder_params);
        assert!(
            overflow.is_err(),
            "pushing {ring_size} + 1 members should fail"
        );
    }
}
