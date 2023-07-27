// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/polyarray.h"

using namespace seal::util;

namespace seal
{
    PolynomialArray::PolynomialArray(
        const SEALContext &context,
        const Ciphertext &ciphertext,
        MemoryPoolHandle pool
    ) : PolynomialArray(pool) {

        auto &parms = context.first_context_data()->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto coeff_modulus_size = ciphertext.coeff_modulus_size();
        auto poly_modulus_degree = ciphertext.poly_modulus_degree();
        auto num_poly = ciphertext.size();

        reserve(num_poly, poly_modulus_degree, coeff_modulus);

        // The ciphertexts are stored in the same RNS format as the
        // other polynomial arrays.
        for (int i = 0; i < num_poly; i++) {
            const auto data_ptr = ciphertext.data() + i * (poly_modulus_degree * coeff_modulus_size);
            insert_polynomial(i, data_ptr);
        }
    }

    PolynomialArray::PolynomialArray(
        const SEALContext &context,
        const PublicKey &public_key,
        MemoryPoolHandle pool
    ) : PolynomialArray(pool) {

        auto &ciphertext = public_key.data();
        auto &parms = context.first_context_data()->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto coeff_modulus_size = ciphertext.coeff_modulus_size();
        auto poly_modulus_degree = ciphertext.poly_modulus_degree();
        auto num_poly = ciphertext.size();

        reserve(num_poly, poly_modulus_degree, coeff_modulus);

        // The ciphertexts are stored in the same RNS format as the
        // other polynomial arrays.
        for (int i = 0; i < num_poly; i++) {
            const auto data_ptr = ciphertext.data() + i * (poly_modulus_degree * coeff_modulus_size);
            insert_polynomial(i, data_ptr);
        }
    }

    PolynomialArray::PolynomialArray(const PolynomialArray &copy): PolynomialArray(copy.pool_) {
        // These parameters in the result object are internally stored once
        // reserve is called.
        auto poly_size = copy.poly_size();
        auto coeff_modulus_size = copy.coeff_modulus_size();
        auto coeff_modulus = copy.coeff_modulus_;
        auto poly_modulus_degree = copy.poly_modulus_degree();

        // Then reserve
        reserve(poly_size, poly_modulus_degree, coeff_modulus);

        for (std::size_t i = 0; i < poly_size; i++) {
            if (copy.polynomial_reserved_[i]) {
                const auto data_ptr = copy.get_polynomial(i);
                insert_polynomial(i, data_ptr);
            }
        }
    }

    void PolynomialArray::reserve(
        std::size_t poly_size,
        std::size_t coeff_size,
        const std::vector<Modulus> &rnsbase
    ) {
        if (reserved_) {
            throw std::logic_error("PolynomialArray can only be reserved once.");
        }

        set_modulus(rnsbase);

        poly_size_ = poly_size;
        coeff_size_ = coeff_size;
        poly_len_ = coeff_size * coeff_modulus_size_;
        len_ = poly_size_ * poly_len_;

        data_ = allocate<std::uint64_t>(len_, pool_);

        polynomial_reserved_.resize(poly_size_, false);
        reserved_ = true;
    }

    void PolynomialArray::to_multiprecision() {
        // If we are already in multiprecision form then we don't need to convert back.
        if (!is_rns_) {
            return;
        }

        for (int i = 0; i < poly_size_; i++) {
            auto poly_start = get_polynomial(i);
            rnsbase_->compose_array(poly_start, coeff_size_, pool_);
        }

        is_rns_ = false;
    }

    /**
    Modifies the polynomial array in place to RNS form.
    */
    void PolynomialArray::to_rns() {
        // If we are already in RNS form then we don't need to convert back.
        if (is_rns_) {
            return;
        }

        for (int i = 0; i < poly_size_; i++) {
            auto poly_start = get_polynomial(i);
            rnsbase_->decompose_array(poly_start, coeff_size_, pool_);
        }

        is_rns_ = true;
    }
}