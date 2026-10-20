package io.appguard.android;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

/** Installation key handle. Private key material never leaves Android Keystore through this API. */
public final class AndroidInstallationKey implements RequestSigner.PublicSigningKey {
    public enum Requirement { ANY_KEYSTORE, HARDWARE_REQUIRED, STRONGBOX_REQUIRED }
    public enum Backing { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX, HARDWARE_UNSPECIFIED, UNKNOWN }
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Backing backing;
    private AndroidInstallationKey(PrivateKey privateKey, PublicKey publicKey, Backing backing) {
        this.privateKey = privateKey; this.publicKey = publicKey; this.backing = backing;
    }

    /** Never regenerates, deletes or replaces an existing alias, including after validation failure. */
    public static synchronized AndroidInstallationKey getOrCreate(Context context, String alias,
                                                                   Requirement requirement) throws GeneralSecurityException {
        if (context == null || requirement == null) throw new IllegalArgumentException("INVALID_KEY_CONFIGURATION");
        RequestSigner.validateIdentifier(alias);
        if (requirement == Requirement.STRONGBOX_REQUIRED && (Build.VERSION.SDK_INT < 31
                || !context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))) {
            throw new GeneralSecurityException("HARDWARE_REQUIREMENT_UNAVAILABLE");
        }
        try {
            Path directory = context.getNoBackupFilesDir().toPath().resolve("appguard-keystore-locks");
            Files.createDirectories(directory);
            String name = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(alias.getBytes(StandardCharsets.US_ASCII))) + ".lock";
            try (FileChannel channel = FileChannel.open(directory.resolve(name), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock lock = channel.tryLock()) {
                if (lock == null) throw new GeneralSecurityException("KEYSTORE_BUSY");
                KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
                if (!store.containsAlias(alias)) {
                    KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false);
                    if (requirement == Requirement.STRONGBOX_REQUIRED) spec.setIsStrongBoxBacked(true);
                    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                    generator.initialize(spec.build()); generator.generateKeyPair();
                }
                return loadValidated(store, alias, requirement);
            }
        } catch (IOException | RuntimeException error) {
            throw new GeneralSecurityException("KEYSTORE_UNAVAILABLE", error);
        }
    }

    private static AndroidInstallationKey loadValidated(KeyStore store, String alias, Requirement requirement)
            throws GeneralSecurityException {
        KeyStore.Entry entry = store.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) throw new GeneralSecurityException("KEY_REJECTED");
        KeyStore.PrivateKeyEntry privateEntry = (KeyStore.PrivateKeyEntry) entry;
        PrivateKey privateKey = privateEntry.getPrivateKey(); PublicKey publicKey = privateEntry.getCertificate().getPublicKey();
        EcdsaP256.requireP256(privateKey); EcdsaP256.requireP256(publicKey);
        KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(privateKey, KeyInfo.class);
        if (!alias.equals(info.getKeystoreAlias()) || info.getOrigin() != KeyProperties.ORIGIN_GENERATED
                || info.getKeySize() != 256 || (info.getPurposes() & KeyProperties.PURPOSE_SIGN) == 0
                || !Arrays.asList(info.getDigests()).contains(KeyProperties.DIGEST_SHA256) || info.isUserAuthenticationRequired()
                || (Build.VERSION.SDK_INT >= 31 && info.getRemainingUsageCount() != KeyProperties.UNRESTRICTED_USAGE_COUNT)) {
            throw new GeneralSecurityException("KEY_REJECTED");
        }
        Backing backing = backing(info);
        if (requirement == Requirement.STRONGBOX_REQUIRED && backing != Backing.STRONGBOX
                || requirement == Requirement.HARDWARE_REQUIRED && !hardware(backing)) {
            throw new GeneralSecurityException("HARDWARE_REQUIREMENT_UNAVAILABLE");
        }
        AndroidInstallationKey result = new AndroidInstallationKey(privateKey, publicKey, backing);
        // Detect invalidated/restricted keys and mismatched public certificates before returning a handle.
        JcaSigningKey.provePair(result, publicKey);
        return result;
    }
    private static boolean hardware(Backing backing) {
        return backing == Backing.TRUSTED_ENVIRONMENT || backing == Backing.STRONGBOX || backing == Backing.HARDWARE_UNSPECIFIED;
    }
    @SuppressWarnings("deprecation")
    private static Backing backing(KeyInfo info) {
        if (Build.VERSION.SDK_INT >= 31) {
            switch (info.getSecurityLevel()) {
                case KeyProperties.SECURITY_LEVEL_SOFTWARE: return Backing.SOFTWARE;
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return Backing.TRUSTED_ENVIRONMENT;
                case KeyProperties.SECURITY_LEVEL_STRONGBOX: return Backing.STRONGBOX;
                case KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE: return Backing.HARDWARE_UNSPECIFIED;
                default: return Backing.UNKNOWN;
            }
        }
        return info.isInsideSecureHardware() ? Backing.HARDWARE_UNSPECIFIED : Backing.SOFTWARE;
    }
    public Backing backing() { return backing; }
    public String publicKeyPem() throws GeneralSecurityException { return EcdsaP256.publicPem(publicKey); }
    @Override public byte[] publicKeySpki() { return publicKey.getEncoded().clone(); }
    @Override public byte[] signDer(byte[] base) throws GeneralSecurityException {
        if (base == null) throw new GeneralSecurityException("INVALID_SIGNING_INPUT");
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey); signature.update(base); return signature.sign();
    }
}
