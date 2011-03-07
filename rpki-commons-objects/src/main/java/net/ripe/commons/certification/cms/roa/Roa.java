package net.ripe.commons.certification.cms.roa;

import java.util.List;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.ipresource.Asn;

public interface Roa {

    Asn getAsn();

    ValidityPeriod getValidityPeriod();

    List<RoaPrefix> getPrefixes();

}
