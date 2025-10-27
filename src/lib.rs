#[cfg(feature = "small-ring")]
pub const RING_SIZE: usize = 255;
#[cfg(not(feature = "small-ring"))]
pub const RING_SIZE: usize = 16127;


#[cfg(test)]
mod tests {
    use super::RING_SIZE;
    use ark_vrf::ring::SrsLookup;
    use verifiable::ring_vrf_impl::{
        ring_verifier_builder_params, BandersnatchVrfVerifiable, RingBuilderParams, StaticChunk,
    };
    use verifiable::GenerateVerifiable;

    type VerifiableImpl = BandersnatchVrfVerifiable;
    type Intermediate = <VerifiableImpl as GenerateVerifiable>::Intermediate;
    type Member = <VerifiableImpl as GenerateVerifiable>::Member;

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
        params: &RingBuilderParams,
    ) -> Result<(), ()> {
        VerifiableImpl::push_members(intermediate, members, |range| {
            params
                .lookup(range)
                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
                .ok_or(())
        })
    }

    #[test]
    fn ring_size_is_the_push_limit() {
        let builder_params = ring_verifier_builder_params();

        let mut builder = VerifiableImpl::start_members();
        for idx in 0..RING_SIZE {
            let result =
                push_with_lookup(&mut builder, std::iter::once(member_at(idx)), &builder_params);
            assert!(
                result.is_ok(),
                "failed while pushing member {idx} before reaching the expected ring size limit {RING_SIZE}"
            );
        }

        let overflow =
            push_with_lookup(&mut builder, std::iter::once(member_at(RING_SIZE)), &builder_params);
        assert!(
            overflow.is_err(),
            "pushing {RING_SIZE} + 1 members should fail"
        );
    }
}


