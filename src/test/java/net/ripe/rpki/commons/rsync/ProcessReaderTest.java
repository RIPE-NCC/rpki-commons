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
