package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.ValidityPeriod;

import java.util.List;

public interface Roa {

    Asn getAsn();

    ValidityPeriod getValidityPeriod();

    List<RoaPrefix> getPrefixes();

}
