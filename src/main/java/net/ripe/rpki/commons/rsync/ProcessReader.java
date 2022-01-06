package net.ripe.rpki.commons.rsync;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;


public class ProcessReader extends Thread {

    private InputStream input;
    private OutputStream output;
    private List<String> lines;


    public ProcessReader(InputStream input) {
        this.input = input;
    }

    public ProcessReader(InputStream input, OutputStream output) {
        this.input = input;
        this.output = output;
    }

    public List<String> getLines() {
        return lines;
    }

    @Override
    public void run() {
        try {
            String line;
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            PrintWriter printer = null;

            if (output == null) {
                lines = new ArrayList<String>();
            } else {
                printer = new PrintWriter(output);
            }

            while ((line = reader.readLine()) != null) {
                if (output == null) {
                    lines.add(line);
                } else {
                    printer.println(line);
                    printer.flush();
                }
            }
            reader.close();
        } catch (IOException e) {
            throw new ProcessReaderException(e);
        }
    }
}
