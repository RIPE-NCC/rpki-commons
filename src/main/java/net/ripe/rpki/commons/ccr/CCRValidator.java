package net.ripe.rpki.commons.ccr;

import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@UtilityClass
public class CCRValidator {
    /**
     * Validate aspects of the encoded CCR state and throw {@link InvalidState} errors for anomalies.
     */
    public static void validate(RPKICanonicalCacheRepresentation ccr) throws InvalidState {
        if (allEmpty(ccr.mfts(), ccr.vrps(), ccr.vaps(), ccr.tas(), ccr.rks())) {
            throw new InvalidState("at least one of mfts, vrps, vaps, tas, or rks MUST be present");
        }
        var mfts = ccr.mfts();
        if (mfts.isPresent()) {
            validate(mfts.get());
        }
        var vrps = ccr.vrps();
        if (vrps.isPresent()) {
            validate(vrps.get());
        }
        var vaps = ccr.vaps();
        if (vaps.isPresent()) {
            validate(vaps.get());
        }
        var tas = ccr.tas();
        if (tas.isPresent()) {
            validate(tas.get());
        }
        var rks = ccr.rks();
        if (rks.isPresent()) {
            validate(rks.get());
        }
    }

    private static void validate(ManifestState mfts) throws InvalidState {
        ManifestInstance last = null;
        for (var mi : mfts.mis()) {
            validate(mi);
            if (last != null && mi.hash().equals(last.hash())) {
                throw new InvalidState("duplicate has found in Manifest state: %s".formatted(mi.hash()));
            }
            last = mi;
        }
        var computed = ManifestState.from(mfts.mis());
        if (!mfts.mis().equals(computed.mis())) {
            throw new InvalidState("invalid order of manifest instances");
        }
        if (!mfts.mostRecentUpdate().equals(computed.mostRecentUpdate())) {
            throw new InvalidState("mostRecentUpdate does not match latest thisUpdate of manifest instances");
        }
        if (!mfts.hash().equals(computed.hash())) {
            throw new InvalidState("invalid hash of Manifest state");
        }
    }

    private static void validate(ManifestInstance mft) throws InvalidState {
        if (mft.size() < 1000) {
            throw new InvalidState("invalid manifest size: %d".formatted(mft.size()));
        }
        if (mft.locations().isEmpty()) {
            throw new InvalidState("manifest must have at least one location");
        }
        if (mft.subordinates().map(List::isEmpty).orElse(false)) {
            throw new InvalidState("manifest must have at least one subordinate, when specified");
        }
        var computed = ManifestInstance.from(mft.hash(), mft.size(), mft.aki(), mft.manifestNumber(), mft.thisUpdate(), mft.locations(), mft.subordinates());
        if (!mft.subordinates().equals(computed.subordinates())) {
            throw new InvalidState("invalid order of manifest subordinates");
        }
        if (!mft.subordinates().map(xs -> (long) xs.size()).equals(
            mft.subordinates().map(x -> x.stream().distinct().count()))
        ) {
            throw new InvalidState("duplicate Subject Key Identifier in subordinates");
        }
    }

    private static void validate(ROAPayloadState vrps) throws InvalidState {
        var computed = ROAPayloadState.from(vrps.rps());
        if (!vrps.rps().equals(computed.rps())) {
            throw new InvalidState("invalid order of ROA payload sets");
        }
        ROAPayloadSet last = null;
        for (var rp : vrps.rps()) {
            validate(rp);
            if (last != null && rp.asID().equals(last.asID())) {
                throw new InvalidState("duplicate AS in ROA payloads: %d".formatted(rp.asID()));
            }
            last = rp;
        }
        if (!vrps.hash().equals(computed.hash())) {
            throw new InvalidState("invalid hash of ROA Payload state");
        }
    }

    private static void validate(ROAPayloadSet rp) throws InvalidState {
        var computed = ROAPayloadSet.from(rp.asID(), rp.ipv4AddrBlocks(), rp.ipv6AddrBlocks());
        if (!rp.ipv4AddrBlocks().equals(computed.ipv4AddrBlocks())) {
            throw new InvalidState("invalid order of ipv4AddrBlocks");
        }
        if (!rp.ipv6AddrBlocks().equals(computed.ipv6AddrBlocks())) {
            throw new InvalidState("invalid order of ipv6AddrBlocks");
        }
        if (allEmpty(rp.ipv4AddrBlocks(), rp.ipv6AddrBlocks())) {
            throw new InvalidState("ROA must have at least one IP block");
        }
    }

    private static void validate(ASPAPayloadState vaps) throws InvalidState {
        var computed = ASPAPayloadState.from(vaps.aps());

        if (!vaps.aps().equals(computed.aps())) {
            throw new InvalidState("invalid order of ASPA Payload sets");
        }
        ASPAPayloadSet last = null;
        for (var ap : vaps.aps()) {
            validate(ap);
            if (last != null && ap.customerASID() == last.customerASID()) {
                throw new InvalidState("duplicate customer AS in ASPA payloads: %d".formatted(ap.customerASID()));
            }
            last = ap;
        }
        if (!vaps.hash().equals(computed.hash())) {
            throw new InvalidState("invalid hash of ASPA Payload state");
        }
    }

    private static void validate(ASPAPayloadSet ap) throws InvalidState {
        if (ap.providers().isEmpty()) {
            throw new InvalidState("ASPA object must have at least one provider");
        }
        var computed = ASPAPayloadSet.from(ap.customerASID(), ap.providers());
        if (!ap.providers().equals(computed.providers())) {
            throw new InvalidState("invalid order of providers");
        }
    }

    private static void validate(TrustAnchorState tas) throws InvalidState {
        var computed = TrustAnchorState.from(tas.skis());
        if (tas.skis().isEmpty()) {
            throw new InvalidState("TA state must have at least one SKI");
        }
        if (!tas.skis().equals(computed.skis())) {
            throw new InvalidState("invalid order of SKIs");
        }
        if (!tas.hash().equals(computed.hash())) {
            throw new InvalidState("invalid hash of Trust Anchor state");
        }
    }

    private static void validate(RouterKeyState rks) throws InvalidState {
        var computed = RouterKeyState.from((rks.rksets()));
        if (!rks.rksets().equals(computed.rksets())) {
            throw new InvalidState("invalid order of Router Key sets");
        }
        RouterKeySet last = null;
        for (var rk : rks.rksets()) {
            validate(rk);
            if (last != null && rk.asID() == last.asID()) {
                throw new InvalidState("duplicate AS in Router Key state: %d".formatted(rk.asID()));
            }
            last = rk;
        }
        if (!rks.hash().equals(computed.hash())) {
            throw new InvalidState("invalid hash of Router Key state");
        }
    }

    private static void validate(RouterKeySet rk) throws InvalidState {
        var computed = RouterKeySet.from(rk.asID(), rk.routerKeys());
        if (!rk.routerKeys().equals(computed.routerKeys())) {
            throw new InvalidState("invalid order of Router Keys");
        }
        if (rk.routerKeys().isEmpty()) {
            throw new InvalidState("Router Key set must have at least one key");
        }
    }

    private static boolean allEmpty(Optional<?>... xs) {
        return Stream.of(xs).noneMatch(Optional::isPresent);
    }
}
