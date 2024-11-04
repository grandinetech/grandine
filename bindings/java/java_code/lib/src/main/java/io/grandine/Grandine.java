package io.grandine;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class Grandine {
    private static native boolean run();

    private static volatile boolean libraryLoaded = false;
    private static final Object libraryLock = new Object();

    public Grandine() {
        ensureLibraryLoaded();
    }

    public void start() {
        this.run();
    }

    private static final String LIBRARY_NAME = "java_grandine";
    private static final String PLATFORM_NATIVE_LIBRARY_NAME = System.mapLibraryName(LIBRARY_NAME);

    private static void ensureLibraryLoaded() {
        if (!libraryLoaded) {
            synchronized (libraryLock) {
                if (!libraryLoaded) {
                    loadNativeLibrary();
                    libraryLoaded = true;
                }
            }
        }
    }

    private static String getNormalizedArchitecture() {
        String osArch = System.getProperty("os.arch").toLowerCase();
        if (osArch.equals("x86_64") || osArch.equals("amd64")) {
            return "x86_64";
        } else if (osArch.equals("aarch64") || osArch.equals("arm64")) {
            return "aarch64";
        } else {
            return osArch;
        }
    }

    /** Loads the appropriate native library based on your platform. */
    private static void loadNativeLibrary() {

        String osName = System.getProperty("os.name").toLowerCase();
        String osArch = getNormalizedArchitecture();
        String libraryResourcePath = null;
        System.out.println("name: " + osName + " arch:" + osArch + " platform: " + PLATFORM_NATIVE_LIBRARY_NAME);
        if (osName.contains("win")) {
            if (osArch.contains("x86_64")) {
                libraryResourcePath = "/x86_64-pc-windows-gnu/" + PLATFORM_NATIVE_LIBRARY_NAME;
            } else if (osArch.contains("x86")) {
                // We do not support 32 bit windows
            } else if (osArch.contains("aarch64")) {
                // We currently do not support arm on windows
            }
        } else if (osName.contains("mac")) {
            if (osArch.contains("x86_64")) {
                libraryResourcePath = "/x86_64-apple-darwin/" + PLATFORM_NATIVE_LIBRARY_NAME;
            } else if (osArch.contains("aarch64")) {
                libraryResourcePath = "/aarch64-apple-darwin/" + PLATFORM_NATIVE_LIBRARY_NAME;
            }
        } else if (osName.contains("linux")) {
            if (osArch.contains("x86_64")) {
                libraryResourcePath = "/x86_64-unknown-linux-gnu/" + PLATFORM_NATIVE_LIBRARY_NAME;
            } else if (osArch.contains("aarch64")) {
                libraryResourcePath = "/aarch64-unknown-linux-gnu/" + PLATFORM_NATIVE_LIBRARY_NAME;
            }
        }

        if (libraryResourcePath == null) {
            throw new UnsupportedOperationException("Unsupported OS or architecture: " + osName + ", " + osArch);
        }

        InputStream libraryResource = Grandine.class.getResourceAsStream(libraryResourcePath);

        if (libraryResource == null) {
            try {
                System.loadLibrary(LIBRARY_NAME);
            } catch (UnsatisfiedLinkError __) {
                String exceptionMessage =
                        String.format(
                                "Couldn't load native library (%s). It wasn't available at %s or the library path.",
                                LIBRARY_NAME, libraryResourcePath);
                throw new RuntimeException(exceptionMessage);
            }
        } else {
            try {
                Path tempDir = Files.createTempDirectory(LIBRARY_NAME + "@");
                tempDir.toFile().deleteOnExit();
                Path tempDll = tempDir.resolve(PLATFORM_NATIVE_LIBRARY_NAME);
                tempDll.toFile().deleteOnExit();
                Files.copy(libraryResource, tempDll, StandardCopyOption.REPLACE_EXISTING);
                libraryResource.close();
                System.load(tempDll.toString());
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
    }
}
