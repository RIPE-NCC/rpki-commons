/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.validation.roa;

import static junit.framework.Assert.*;
import static net.ripe.commons.certification.cms.roa.RoaCmsParserTest.*;

import java.util.Arrays;
import java.util.List;

import net.ripe.commons.certification.cms.roa.Roa;
import net.ripe.commons.certification.cms.roa.RoaCmsTest;
import net.ripe.commons.certification.cms.roa.RoaPrefix;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


public class RouteOriginValidationPolicyTest {
    private RouteOriginValidationPolicy subject;

    @BeforeClass
    public static void should_verify_assumptions() {
        Roa roa = roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20));
        assertEquals(TEST_ASN, roa.getAsn());
    }
    
    static Roa roa(RoaPrefix... roaPrefixes) {
        return RoaCmsTest.createRoaCms(Arrays.asList(roaPrefixes));
    }
    
    @Before
    public void setup() {
        subject = new RouteOriginValidationPolicy();
    }
    
    @Test
    public void routes_with_non_intersecting_prefix_and_matching_ASN_should_be_UNKNOWN() {
        assertEquals(RouteValidityState.UNKNOWN, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.169.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_non_intersecting_prefix_and_non_matching_ASN_should_be_UNKNOWN() {
        assertEquals(RouteValidityState.UNKNOWN, subject.determineRouteValidityState(
                new AnnouncedRoute(Asn.parse("AS124"), IpRange.parse("192.169.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_covering_aggregate_prefix_and_matching_ASN_should_be_UNKNOWN() {
        assertEquals(RouteValidityState.UNKNOWN, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/15")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_covering_aggregate_prefix_and_non_matching_ASN_should_be_UNKNOWN() {
        assertEquals(RouteValidityState.UNKNOWN, subject.determineRouteValidityState(
                new AnnouncedRoute(Asn.parse("AS124"), IpRange.parse("192.168.0.0/15")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_matching_prefix_and_ASN_should_be_VALID() {
        assertEquals(RouteValidityState.VALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_precise_matching_prefix_and_ASN_should_be_VALID() {
        assertEquals(RouteValidityState.VALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/16")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16")))));
    }
    
    @Test
    public void routes_with_matching_prefix_but_non_matching_ASN_should_be_INVALID() {
        assertEquals(RouteValidityState.INVALID, subject.determineRouteValidityState(
                new AnnouncedRoute(Asn.parse("AS124"), IpRange.parse("192.168.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_more_specific_prefix_and_matching_ASN_should_be_INVALID() {
        assertEquals(RouteValidityState.INVALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/21")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_more_specific_prefix_and_non_matching_ASN_should_be_INVALID() {
        assertEquals(RouteValidityState.INVALID, subject.determineRouteValidityState(
                new AnnouncedRoute(Asn.parse("AS124"), IpRange.parse("192.168.0.0/21")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }

    @Test
    public void routes_with_more_specific_prefix_and_roa_with_default_maxlength_and_matching_ASN_should_be_INVALID() {
        assertEquals(RouteValidityState.INVALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16")))));
    }
    
    @Test
    public void routes_without_origin_ASN_should_be_INVALID() {
        assertEquals(RouteValidityState.INVALID, subject.determineRouteValidityState(
                new AnnouncedRoute(null, IpRange.parse("192.168.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_any_matching_prefix_and_ASN_should_be_VALID() {
        assertEquals(RouteValidityState.VALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/20")), roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20), new RoaPrefix(IpRange.parse("192.169.0.0/16"), 20))));
    }
    
    @Test
    public void routes_with_at_least_one_valid_roa_should_be_VALID() {
        List<Roa> roaList = Arrays.asList(roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20)), roa(new RoaPrefix(IpRange.parse("10.10.0.0/16"), 20)));
        assertEquals(RouteValidityState.VALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/20")), roaList));
    }
    
    @Test
    public void routes_with_at_least_one_invalid_roa_and_without_valid_roas_should_be_INVALID() {
        List<Roa> roaList = Arrays.asList(roa(new RoaPrefix(IpRange.parse("192.168.0.0/16"), 20)), roa(new RoaPrefix(IpRange.parse("10.10.0.0/16"), 20)));
        assertEquals(RouteValidityState.INVALID, subject.determineRouteValidityState(
                new AnnouncedRoute(TEST_ASN, IpRange.parse("192.168.0.0/24")), roaList));
    }
    
}