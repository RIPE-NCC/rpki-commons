/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.etree.NestedIntervalMap;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;
import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParserTest.*;


public class RouteOriginValidationPolicyTest {

    private RouteOriginValidationPolicy subject;

    static NestedIntervalMap<IpResource, List<AllowedRoute>> roa(RoaPrefix... roaPrefixes) {
        RoaCms roa = RoaCmsTest.createRoaCms(Arrays.asList(roaPrefixes));
        List<AllowedRoute> allowed = AllowedRoute.fromRoas(Collections.singletonList(roa));
        return RouteOriginValidationPolicy.allowedRoutesToNestedIntervalMap(allowed);
    }

    @Before
    public void setup() {
        subject = new RouteOriginValidationPolicy();
    }

    @Test
    public void routes_with_non_intersecting_prefix_and_matching_ASN_should_be_UNKNOWN() {
        testValidatityDetermination("192.168.0.0/16", 20, TEST_ASN, "192.169.0.0/20", RouteValidityState.UNKNOWN);
    }

    @Test
    public void routes_with_non_intersecting_prefix_and_non_matching_ASN_should_be_UNKNOWN() {
        testValidatityDetermination("192.168.0.0/16", 20, Asn.parse("AS124"), "192.169.0.0/20", RouteValidityState.UNKNOWN);
    }

    @Test
    public void routes_with_covering_aggregate_prefix_and_matching_ASN_should_be_UNKNOWN() {
        testValidatityDetermination("192.168.0.0/16", 20, TEST_ASN, "192.168.0.0/15", RouteValidityState.UNKNOWN);
    }

    @Test
    public void routes_with_covering_aggregate_prefix_and_non_matching_ASN_should_be_UNKNOWN() {
        testValidatityDetermination("192.168.0.0/16", 20, Asn.parse("AS124"), "192.168.0.0/15", RouteValidityState.UNKNOWN);
    }

    @Test
    public void routes_with_matching_prefix_and_ASN_should_be_VALID() {
        testValidatityDetermination("192.168.0.0/16", 20, TEST_ASN, "192.168.0.0/20", RouteValidityState.VALID);
    }

    @Test
    public void routes_with_precise_matching_prefix_and_ASN_should_be_VALID() {
        testValidatityDetermination("192.168.0.0/16", 16, TEST_ASN, "192.168.0.0/16", RouteValidityState.VALID);
    }

    @Test
    public void routes_with_matching_prefix_but_non_matching_ASN_should_be_INVALID_ANS() {
        testValidatityDetermination("192.168.0.0/16", 20, Asn.parse("AS124"), "192.168.0.0/20", RouteValidityState.INVALID_ASN);
    }

    @Test
    public void routes_with_more_specific_prefix_and_matching_ASN_should_be_INVALID_LENGTH() {
        testValidatityDetermination("192.168.0.0/16", 20, TEST_ASN, "192.168.0.0/21", RouteValidityState.INVALID_LENGTH);
    }

    @Test
    public void routes_with_more_specific_prefix_and_non_matching_ASN_should_be_INVALID_ASN() {
        testValidatityDetermination("192.168.0.0/16", 20, Asn.parse("AS124"), "192.168.0.0/21", RouteValidityState.INVALID_ASN);
    }

    @Test
    public void routes_with_more_specific_prefix_and_roa_with_default_maxlength_and_matching_ASN_should_be_INVALID_LENGTH() {
        testValidatityDetermination("192.168.0.0/16", 16, TEST_ASN, "192.168.0.0/20", RouteValidityState.INVALID_LENGTH);
    }

    @Test
    public void routes_with_any_matching_prefix_and_ASN_should_be_VALID() {
        NestedIntervalMap<IpResource, List<AllowedRoute>> prefixes = roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20), new RoaPrefix(IpRange.parse("192.169.0.0/16"), 20));

        AnnouncedRoute route = new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/20"));
        RouteValidityState validityStateFound = subject.validateAnnouncedRoute(prefixes, route);
        assertEquals(RouteValidityState.VALID, validityStateFound);
    }

    @Test
    public void routes_with_at_least_one_valid_roa_should_be_VALID() {
        NestedIntervalMap<IpResource, List<AllowedRoute>> prefixes = roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20), new RoaPrefix(IpRange.parse("10.10.0.0/16")));

        AnnouncedRoute route = new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/20"));
        RouteValidityState validityStateFound = subject.validateAnnouncedRoute(prefixes, route);
        assertEquals(RouteValidityState.VALID, validityStateFound);
    }

    @Test
    public void routes_with_at_least_one_invalid_roa_and_without_valid_roas_should_be_INVALID() {
        NestedIntervalMap<IpResource, List<AllowedRoute>> prefixes = roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20), new RoaPrefix(IpRange.parse("10.10.0.0/16")));

        AnnouncedRoute route = new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/24"));
        RouteValidityState validityStateFound = subject.validateAnnouncedRoute(prefixes, route);
        assertEquals(RouteValidityState.INVALID_LENGTH, validityStateFound);

    }

    private void testValidatityDetermination(String roaIpPrefix, int roaMaxLength, Asn routeAsn, String routePrefix, RouteValidityState expectedResult) {
        NestedIntervalMap<IpResource, List<AllowedRoute>> rtrPrefixes = roa(new RoaPrefix(IpRange.parse(roaIpPrefix), roaMaxLength));
        AnnouncedRoute route = new AnnouncedRoute(routeAsn, IpRange.parse(routePrefix));
        RouteValidityState validityStateFound = subject.validateAnnouncedRoute(rtrPrefixes, route);
        assertEquals(expectedResult, validityStateFound);
    }

}
