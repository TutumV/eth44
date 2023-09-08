try:
    from eth44.ecdsa_openssl import ECPointAffine, EllipticCurve, secp256k1
except:
    from eth44.ecdsa_python import ECPointAffine, EllipticCurve, secp256k1
