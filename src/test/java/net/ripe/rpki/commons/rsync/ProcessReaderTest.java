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
package net.ripe.rpki.commons.rsync;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.OutputStream;

import static org.junit.Assert.*;


public class ProcessReaderTest {

    private final String firstLine = "first line";
    private final String secondLine = "second line";
    private final String text = firstLine + System.getProperty("line.separator") + secondLine + System.getProperty("line.separator");


    @Test
    public void shouldReadStreamAndCollectOutput() throws FileNotFoundException, InterruptedException {
        ProcessReader processReader = new ProcessReader(new ByteArrayInputStream(text.getBytes()));
        processReader.start();

        processReader.join();

        assertNotNull(processReader.getLines());
        assertTrue(processReader.getLines().size() == 2);
        assertEquals(processReader.getLines().get(0), firstLine);
        assertEquals(processReader.getLines().get(1), secondLine);
    }

    @Test
    public void shouldReadStreamAndPrintOutput() throws InterruptedException {
        OutputStream out = new ByteArrayOutputStream();

        ProcessReader processReader = new ProcessReader(new ByteArrayInputStream(text.getBytes()), out);
        processReader.start();

        processReader.join();

        assertNull(processReader.getLines());
        assertEquals(out.toString(), text);
    }
}
