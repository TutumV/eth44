import hashlib
import math
import random

from ctypes import c_char_p
from ctypes import c_void_p
from ctypes import create_string_buffer

from eth44.ecdsa_base import EllipticCurveBase
from eth44.ecdsa_base import Point
from eth44.openssl import (
    lc,
    point_new_from_ints,
    point_get_xy_ints,
    get_curve_params,
    int_to_bn,
    bn_to_int,
    new_key,
    get_public_key_ints,
    set_public_key_from_ints,
    sig_new_from_ints,
)


class ECPointAffine(object):
    """An affine (2D) representation of an elliptic curve point.
    In this implementation, only the minimum functionality
    required for bitcoin crypto-API compatibility is provided.
    All math operations make use of OpenSSL primitives.
    Args:
        curve (EllipticCurve): The curve the point is on.
        x (int): x component of point.
        y (int): y component of point.
        infinity (bool): Whether or not this point is at infinity.
    Returns:
        ECPointAffine: the point formed by (x, y) on curve.
    """

    def __init__(self, curve, x, y, infinity=False):
        self.x = x
        self.y = y
        self.curve = curve
        self.infinity = infinity

    def __str__(self):
        return "(0x%x, 0x%x)" % (self.x, self.y)

    def __eq__(self, b):
        return ((self.x == b.x) and (self.y == b.y)) or (self.infinity and b.infinity)

    def __add__(self, b):
        assert self.curve == b.curve

        a_pt = point_new_from_ints(self.curve.os_group, self.x, self.y, self.infinity)
        b_pt = point_new_from_ints(b.curve.os_group, b.x, b.y, b.infinity)
        lc.EC_POINT_add(self.curve.os_group, a_pt, a_pt, b_pt, None)

        x, y, inf = point_get_xy_ints(self.curve.os_group, a_pt)

        lc.EC_POINT_free(a_pt)
        lc.EC_POINT_free(b_pt)

        return ECPointAffine(self.curve, x, y, inf)

    @property
    def compressed_bytes(self):
        """Returns the compressed bytes for this point.
        If pt.y is odd, 0x03 is pre-pended to pt.x.
        If pt.y is even, 0x02 is pre-pended to pt.x.
        Returns:
            bytes: Compressed byte representation.
        """
        nbytes = math.ceil(self.curve.nlen / 8)
        return bytes([(self.y & 0x1) + 0x02]) + self.x.to_bytes(nbytes, "big")

    def __bytes__(self):
        """Returns the full-uncompressed point"""
        nbytes = math.ceil(self.curve.nlen / 8)
        return (
            bytes([0x04])
            + self.x.to_bytes(nbytes, "big")
            + self.y.to_bytes(nbytes, "big")
        )


class EllipticCurve(EllipticCurveBase):
    """A generic class for elliptic curves and operations on them.
    The curves must be of the form: y^2 = x^3 + a*x + b.
    Args:
        hash_function (function): The function to use for hashing messages.
    """

    curve_name = None

    def __init__(self, hash_function):
        super().__init__(hash_function)
        self.os_group = c_void_p(lc.EC_GROUP_new_by_curve_name(self.curve_name))

        params = get_curve_params(self.os_group)

        self.p = params["p"]
        self.a = params["a"]
        self.b = params["b"]
        self.n = params["n"]
        self.h = params["h"]

        self.nlen = self.n.bit_length()
        self.plen = self.p.bit_length()

        # We keep a pointer to the libcrypto CDLL object so that
        # it is guaranteed to be around when __del__ is called. If
        # we don't, a race condition exists whereby if the garbage
        # collector disposes of lc before this object, we won't
        # be able to free self.os_group (in __del__).
        self._lc = lc

    def __del__(self):
        self._lc.EC_GROUP_free(self.os_group)

    def is_on_curve(self, p):
        """Checks whether a point is on the curve.
        Args:
            p (ECPointAffine): Point to be checked
        Returns:
            bool: True if p is on the curve, False otherwise.
        """
        ec_pt = point_new_from_ints(self.os_group, p.x, p.y)
        on_curve = lc.EC_POINT_is_on_curve(self.os_group, ec_pt, None)
        lc.EC_POINT_free(ec_pt)

        return bool(on_curve)

    def y_from_x(self, x):
        """Computes the y component corresponding to x.
        Since elliptic curves are symmetric about the x-axis,
        the x component (and sign) is all that is required to determine
        a point on the curve.
        Args:
            x (int): x component of the point.
        Returns:
            tuple: both possible y components of the point.
        """
        rv = []
        x_bn = int_to_bn(x)
        for y_bit in [0, 1]:
            # Create a new point
            ec_pt = c_void_p(lc.EC_POINT_new(self.os_group))
            lc.EC_POINT_set_compressed_coordinates_GFp(
                self.os_group, ec_pt, x_bn, y_bit, c_void_p()
            )

            on_curve = lc.EC_POINT_is_on_curve(self.os_group, ec_pt, c_void_p())
            if not on_curve:
                lc.EC_POINT_free(ec_pt)
                rv.append(None)
                continue

            # Get the y value
            _, y, _ = point_get_xy_ints(self.os_group, ec_pt)
            rv.append(y)
            lc.EC_POINT_free(ec_pt)

        lc.BN_free(x_bn)

        return rv

    def gen_key_pair(self, random_generator=random.SystemRandom()):
        """Generates a public/private key pair.
        Args:
            random_generator (generator): The random generator to use.
        Returns:
            tuple:
                A private key in the range of 1 to `self.n - 1`
                and an ECPointAffine containing the public key point.
        """
        private = random_generator.randrange(1, self.n)
        return private, self.public_key(private)

    def public_key(self, private_key):
        """Returns the public (verifying) key for a given private key.
        Args:
            private_key (int): the private key to derive the public key for.
        Returns:
            ECPointAffine: The point representing the public key.
        """
        k = new_key(self.curve_name, private_key)
        pub_x, pub_y, is_inf = get_public_key_ints(k)
        lc.EC_KEY_free(k)
        return ECPointAffine(self, pub_x, pub_y, is_inf)

    def recover_public_key(self, message, signature, recovery_id=None):
        """Recovers possibilities for the public key associated with the
        private key used to sign message and generate signature.
        Since there are multiple possibilities (two for curves with
        co-factor = 1), each possibility that successfully verifies the
        signature is returned.
        Args:
           message (bytes): The message that was signed.
           signature (ECPointAffine): The point representing the signature.
           recovery_id (int) (Optional): If provided, limits the valid x and y
              point to only that described by the recovery_id.
        Returns:
           list(ECPointAffine): List of points representing valid public
           keys that verify signature.
        """
        r = signature.x
        s = signature.y

        ctx = c_void_p(lc.BN_CTX_new())
        lc.BN_CTX_start(ctx)

        order_bn = c_void_p(lc.BN_CTX_get(ctx))
        x_bn = c_void_p(lc.BN_CTX_get(ctx))
        i_bn = c_void_p(lc.BN_CTX_get(ctx))
        in_bn = c_void_p(lc.BN_CTX_get(ctx))
        p_bn = c_void_p(lc.BN_CTX_get(ctx))
        r_bn = c_void_p(lc.BN_CTX_get(ctx))
        s_bn = c_void_p(lc.BN_CTX_get(ctx))
        rinv_bn = c_void_p(lc.BN_CTX_get(ctx))
        z_bn = c_void_p(lc.BN_CTX_get(ctx))
        lc.EC_GROUP_get_order(self.os_group, order_bn, ctx)

        int_to_bn(self.p, p_bn)
        int_to_bn(r, r_bn)
        int_to_bn(s, s_bn)
        lc.BN_mod_inverse(rinv_bn, r_bn, order_bn, ctx)

        if recovery_id is not None:
            i_list = [recovery_id >> 1]
            k_list = [recovery_id & 0x1]
        else:
            i_list = range(2)
            k_list = range(2)

        rv = []
        num_bytes = math.ceil(self.nlen / 8)

        z = int.from_bytes(self.hash_function(message).digest()[:num_bytes], "big")
        int_to_bn(z, z_bn)

        zG = c_void_p(lc.EC_POINT_new(self.os_group))
        sR = c_void_p(lc.EC_POINT_new(self.os_group))
        temp = c_void_p(lc.EC_POINT_new(self.os_group))
        pub_key = c_void_p(lc.EC_POINT_new(self.os_group))
        Rn = c_void_p(lc.EC_POINT_new(self.os_group))

        for i in i_list:
            int_to_bn(i, i_bn)
            lc.BN_mod_mul(in_bn, i_bn, order_bn, p_bn, ctx)
            lc.BN_mod_add(x_bn, r_bn, in_bn, p_bn, ctx)
            x = bn_to_int(x_bn)
            ys = self.y_from_x(x)

            for k in k_list:
                y = ys[k]
                if y & 0x1 != k:
                    y = ys[k ^ 1]

                R = point_new_from_ints(self.os_group, r, y)
                lc.EC_POINT_mul(self.os_group, Rn, None, R, order_bn, ctx)
                if not lc.EC_POINT_is_at_infinity(self.os_group, Rn):
                    continue

                lc.EC_POINT_mul(self.os_group, zG, z_bn, None, None, ctx)
                lc.EC_POINT_invert(self.os_group, zG, ctx)
                lc.EC_POINT_mul(self.os_group, sR, None, R, s_bn, ctx)
                lc.EC_POINT_add(self.os_group, temp, sR, zG, ctx)
                lc.EC_POINT_mul(self.os_group, pub_key, None, temp, rinv_bn, ctx)

                lc.EC_POINT_free(R)

                # Convert to ECPointAffine
                pub_x, pub_y, inf = point_get_xy_ints(self.os_group, pub_key)
                rv.append((ECPointAffine(self, pub_x, pub_y, inf), 2 * i + k))

        lc.EC_POINT_free(zG)
        lc.EC_POINT_free(sR)
        lc.EC_POINT_free(temp)
        lc.EC_POINT_free(pub_key)
        lc.EC_POINT_free(Rn)

        lc.BN_CTX_end(ctx)
        lc.BN_CTX_free(ctx)

        return rv

    def _sign(self, message, private_key, do_hash=True, secret=None):
        # This function computes k, kinv and rp before sending into
        # OpenSSL ECDSA_do_sign_ex() rather than using ECDSA_do_sign()
        # directly. The reason for this is that as of the commit that
        # introduces this comment, OpenSSL only supports deterministic
        # signing nonces (RFC6979) in the master branch and not any
        # release. As a result, we cannot depend on callers having any
        # OpenSSL version capable of RFC6979 deterministic nonces.
        # Nevertheless, computation of kinv (from k) and rp is done
        # using OpenSSL primitives.
        lc.ERR_clear_error()

        hashed = self.hash_function(message).digest() if do_hash else message

        r = 0
        s = 0
        recovery_id = 0

        key = new_key(self.curve_name, private_key)

        ctx = c_void_p(lc.BN_CTX_new())
        lc.BN_CTX_start(ctx)

        order_bn = c_void_p(lc.BN_CTX_get(ctx))
        k_bn = c_void_p(lc.BN_CTX_get(ctx))
        kinv_bn = c_void_p(lc.BN_CTX_get(ctx))
        px_bn = c_void_p(lc.BN_CTX_get(ctx))
        r_bn = c_void_p(lc.BN_CTX_get(ctx))
        lc.EC_GROUP_get_order(self.os_group, order_bn, ctx)

        while r == 0 or s == 0:
            k = self._nonce_rfc6979(private_key, hashed) if secret is None else secret
            int_to_bn(k, k_bn)

            lc.BN_mod_inverse(kinv_bn, k_bn, order_bn, ctx)

            p = c_void_p(lc.EC_POINT_new(self.os_group))
            lc.EC_POINT_mul(self.os_group, p, k_bn, c_void_p(), c_void_p(), ctx)
            assert self.h == 1

            px, py, _ = point_get_xy_ints(self.os_group, p)
            recovery_id = 2 if px > self.n else 0
            recovery_id |= py & 0x1

            # Get r
            int_to_bn(px, px_bn)
            lc.BN_nnmod(r_bn, px_bn, order_bn, ctx)
            r = bn_to_int(r_bn)

            if r == 0:
                continue

            hashed_buf = c_char_p(hashed)
            sig = lc.ECDSA_do_sign_ex(hashed_buf, len(hashed), kinv_bn, r_bn, key)
            err = lc.ERR_peek_error()
            if err:
                err_buf = create_string_buffer(120)
                lc.ERR_error_string(err, err_buf)
                raise Exception("Problem when signing: %s" % err_buf.raw.decode())

            sig_r = bn_to_int(sig.contents.r)
            sig_s = bn_to_int(sig.contents.s)

            if sig_r != r:
                raise ValueError("Didn't get the same r value.")
            s = sig_s

        lc.EC_KEY_free(key)
        lc.BN_CTX_end(ctx)
        lc.BN_CTX_free(ctx)

        return (Point(r, s), recovery_id)

    def verify(self, message, signature, public_key, do_hash=True):
        """Verifies that signature was generated with a private key corresponding
        to public key, operating on message.
        Args:
            message (bytes): The message to be signed
            signature (Point): (r, s) representing the signature
            public_key (ECPointAffine): ECPointAffine of the public key
            do_hash (bool): True if the message should be hashed prior
               to signing, False if not. This should always be left as
               True except in special situations which require doing
               the hash outside (e.g. handling Bitcoin bugs).
        Returns:
            bool: True if the signature is verified, False otherwise.
        """
        r = signature.x
        s = signature.y

        sig = sig_new_from_ints(r, s)

        hashed = self.hash_function(message).digest() if do_hash else message

        key = c_void_p(lc.EC_KEY_new_by_curve_name(self.curve_name))
        set_public_key_from_ints(
            key=key, x=public_key.x, y=public_key.y, infinity=public_key.infinity
        )

        dig_buf = create_string_buffer(hashed)
        verified = lc.ECDSA_do_verify(dig_buf, len(hashed), sig, key)

        lc.ECDSA_SIG_free(sig)
        lc.EC_KEY_free(key)

        return bool(verified)


class p256(EllipticCurve):
    curve_name = lc.OBJ_sn2nid(c_char_p(b"prime256v1"))

    def __init__(self):
        super().__init__(hashlib.sha256)


class secp256k1(EllipticCurve):
    curve_name = lc.OBJ_sn2nid(c_char_p(b"secp256k1"))

    def __init__(self):
        super().__init__(hashlib.sha256)
