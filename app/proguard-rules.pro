# BouncyCastle uses reflection for some provider plumbing; keep the
# lightweight-API classes we call directly (R8 keeps referenced code anyway,
# these rules are defensive).
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.pqc.crypto.mlkem.** { *; }
-keep class org.bouncycastle.pqc.crypto.mldsa.** { *; }
-dontwarn org.bouncycastle.**
