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
package net.ripe.commons.provisioning.identity;

import static org.junit.Assert.*;

import java.net.URI;

import org.junit.Test;


public class ParentIdentitySerializerTest {
    
    static final String exampleXml =
        "<ns0:parent xmlns:ns0=\"http://www.hactrn.net/uris/rpki/myrpki/\" valid_until=\"2012-06-30T04:07:50Z\" service_uri=\"http://localhost:4401/up-down/Alice/Bob\" child_handle=\"Bob\" parent_handle=\"Alice\" version=\"2\">\n" +
        "<ns0:bpki_resource_ta>\n" +
        "MIIDJDCCAgygAwIBAgIBATANBgkqhkiG9w0BAQsFADArMSkwJwYDVQQDEyBBbGlj\n" +
        "ZSBCUEtJIFJlc291cmNlIFRydXN0IEFuY2hvcjAeFw0xMTA3MDEwNDA3MTlaFw0x\n" +
        "MjA2MzAwNDA3MTlaMCsxKTAnBgNVBAMTIEFsaWNlIEJQS0kgUmVzb3VyY2UgVHJ1\n" +
        "c3QgQW5jaG9yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0nVOC7Ik\n" +
        "bc9D3lNPspAp96LEmxqhfWcF70wOk8MHX2skMoHYa3UsyTMOJR4Pv+DRieLbPI8E\n" +
        "ExrLZRqTrY4+OKRG5sekk3zeIc40g4p8jw6aPxlPUFvJAQdsW+iOYljaPhgWMiGH\n" +
        "Qm2ZfsXUlvr8XtmkryGbzcaJy2CaAnUi5dwUmpMx7GEcUz+LpJ6tfyB1aF1CpnBm\n" +
        "pvOhIl+Tlk55Zpo2Nn1Ty0TiTX40fK/ToKZn+/5LkRBKXjGUSWlMyWBVJZVCHo/Z\n" +
        "PLtPbjUr0gczIYp24q4GxmAHbK12GT/4vGdnQCyadKBDF4Kv0BP6TFf+BP3aE2P7\n" +
        "biQa919zuZzfCQIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQj\n" +
        "tovHYOZzUno6MsFjYyKdJZf3NDAfBgNVHSMEGDAWgBQjtovHYOZzUno6MsFjYyKd\n" +
        "JZf3NDANBgkqhkiG9w0BAQsFAAOCAQEApkybLXSqUGFf6TxVz+AXVbMtTr22tUJ+\n" +
        "nMocs6lDsyXt2QC/ef3iPTECfJXJrWxCF3PaAWcjV/QQVw3Z2BqblHPmNPM0DxhJ\n" +
        "OBv065L041zZla4163XSzEzRHJn+99E9jPs15w7if2A1m2XH2W2gg3aSMBSqZXcM\n" +
        "6Z+W6XsH0dx5c10YspJBSXRls7SsKRpS30fCs2+jSYA0AWvxCTfCNmVf6ssMmAyr\n" +
        "6Ynrt3fS0MpprBPxJF3KWveHLhaUxLYefSsnsV6o3nfZYwyDlo9m7t3IQCg+Yg7k\n" +
        "FO2iB8/TDRIdP6bpBvpVrQ13FvWqC6CglZ0fbFRNklotIVxcP1cuNw==\n" +
        "</ns0:bpki_resource_ta>\n" +
        "<ns0:bpki_child_ta>\n" +
        "MIIDIDCCAgigAwIBAgIBATANBgkqhkiG9w0BAQsFADApMScwJQYDVQQDEx5Cb2Ig\n" +
        "QlBLSSBSZXNvdXJjZSBUcnVzdCBBbmNob3IwHhcNMTEwNzAxMDQwNzIzWhcNMTIw\n" +
        "NjMwMDQwNzIzWjApMScwJQYDVQQDEx5Cb2IgQlBLSSBSZXNvdXJjZSBUcnVzdCBB\n" +
        "bmNob3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEk1f7cVzHu3r/\n" +
        "fJ5gkBxnWMNJ1CP0kPtfP8oFOEVVH1lX0MHuFKhdKA4WCkGkeFtGb/4T/nGgsD+z\n" +
        "exZid6RR8zjHkwMLvAl0x6wdKa46XJbFu+wTSu+vlowVY9rGzH+ttv4Fj6E2Y3DG\n" +
        "983/dVNJfXl00+Ts7rlvVcn9lI5dWvzsLoUOdhD4hsyKp53k8i4HexiD+0ugPeh9\n" +
        "4PKiyZOuMjSRNQSBUA3ElqJSRZz7nWvs/j6zhwHdFa+lN56575Mc5mrwr+KePwW5\n" +
        "DLt3izYpjwKffVuxUKPTrhvnOOg5kBBv0ihync21LSLds6jusxaMYUwUElO8KQyn\n" +
        "NUAeGPd/AgMBAAGjUzBRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFORFOC3G\n" +
        "PjYKn7V1/BJHDmZ4W7J+MB8GA1UdIwQYMBaAFORFOC3GPjYKn7V1/BJHDmZ4W7J+\n" +
        "MA0GCSqGSIb3DQEBCwUAA4IBAQBqsP4ENtWTkNdsekYB+4hO/Afq20Ho0W8lyTkM\n" +
        "JO1UFDt/dzFAmTT4uM7pmwuQfqmCYjNDWon8nsdFno4tA0is3aiq6yIMAYzBE5ub\n" +
        "bnJMxldqLoWuakco1wYa3kZFzWPwecxgJ4ZlqTPGu0Loyjibt25IE9MfixyWDw+D\n" +
        "MhyfonLLgFb5jz7A3BTE63vlTp359uDbFb1nRdyoT31s3FUBK8jF4B5pWzPiLdct\n" +
        "bOMVjYUBs8aFC3fDXyGSr/RcjE4OOZQyTkYZn8zCPUJ4KqOPAUV9u9jx2FPvOcA3\n" +
        "1BjcmhYHqott+cnK1ITOjLe9EKejRZv/7/BFsmpzm2Zbq1KA\n" +
        "</ns0:bpki_child_ta><ns0:repository type=\"offer\"/></ns0:parent>";
    
    public static final ParentIdentity PARENT_IDENTITY = new ParentIdentitySerializer().deserialize(exampleXml);

    
    @Test
    public void shouldCreateFromXml() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();
        
        ParentIdentity parentId = serializer.deserialize(exampleXml);
        assertNotNull(parentId);
        assertEquals("Bob", parentId.getChildHandle());
        assertEquals("Alice", parentId.getParentHandle());
        assertEquals(URI.create("http://localhost:4401/up-down/Alice/Bob"), parentId.getUpDownUrl());
        
        assertNotNull(parentId.getParentIdCertificate());
        assertNotNull(parentId.getChildIdCertificate());
        assertEquals("offer", parentId.getRepositoryDefinition().getType());
    }

}
