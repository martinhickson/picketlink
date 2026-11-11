/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.jdeparser;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;

import javax.annotation.processing.Filer;
import javax.annotation.processing.FilerException;

/**
 * A file manager for writing out source files.
 *
 * <p>
 * PicketLink loads this class ahead of {@code jdeparser}. When the logger implementation
 * ({@code *_$logger}) or the message bundle ({@code *_$bundle}) is already a compilation input,
 * {@link Filer#createSourceFile} refuses to recreate it. The existing type is left in place.
 * </p>
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class JFiler {

    /**
     * Get an instance which uses an underlying {@link javax.annotation.processing.Filer}.
     *
     * @param filer the annotation processing filer
     * @return the JDeparser filer
     */
    public static JFiler newInstance(final Filer filer) {
        return new JFiler() {
            @Override
            public OutputStream openStream(final String packageName, final String fileName) throws IOException {
                final StringBuilder sb = new StringBuilder(packageName);
                if (sb.charAt(sb.length() - 1) != '.') {
                    sb.append('.');
                }
                sb.append(fileName);
                final String typeName = sb.toString();
                try {
                    return filer.createSourceFile(typeName).openOutputStream();
                } catch (FilerException alreadyPresent) {
                    if (!alreadyPresent(alreadyPresent)) {
                        throw alreadyPresent;
                    }
                    return new DiscardingOutputStream();
                }
            }
        };
    }

    /**
     * Get an instance which writes to the filesystem.
     *
     * @param target the target source path
     * @return the JDeparser filer
     */
    public static JFiler newInstance(final File target) {
        return new JFiler() {
            @Override
            public OutputStream openStream(final String packageName, final String fileName) throws IOException {
                final File dir = new File(target, packageName.replace('.', File.separatorChar));
                dir.mkdirs();
                return new FileOutputStream(new File(dir, fileName + ".java"));
            }
        };
    }

    /**
     * Construct a new instance.
     */
    protected JFiler() {
    }

    private String encoding = "utf-8";

    /**
     * Get the file encoding to use.
     *
     * @return the file encoding
     */
    public String getEncoding() {
        return encoding;
    }

    /**
     * Set the file encoding to use.
     *
     * @param encoding the file encoding
     */
    public void setEncoding(final String encoding) {
        this.encoding = encoding;
    }

    /**
     * Open an output stream for writing the given file.
     *
     * @param packageName the package name
     * @param fileName the file name
     * @return the output stream
     * @throws IOException if an error occurs during write
     */
    public abstract OutputStream openStream(String packageName, String fileName) throws IOException;

    /**
     * Open a writer for the given file.  The default implementation calls {@link #openStream(String, String)} and wraps
     * the result with an {@link OutputStreamWriter} using the configured file encoding.
     *
     * @param packageName the package name
     * @param fileName the file name
     * @return the writer
     * @throws IOException if an error occurs during write
     */
    public Writer openWriter(String packageName, String fileName) throws IOException {
        return new OutputStreamWriter(openStream(packageName, fileName), encoding);
    }

    private static boolean alreadyPresent(final FilerException failure) {
        final String message = failure.getMessage();
        return message != null && message.startsWith("Attempt to recreate a file for type ");
    }

    /**
     * Drops a second write. The type is already on the compilation source path, so javac compiles that copy.
     */
    private static final class DiscardingOutputStream extends OutputStream {
        @Override
        public void write(final int value) {
        }

        @Override
        public void write(final byte[] bytes, final int offset, final int length) {
        }
    }
}
