#!/usr/bin/env bash

# An array lets us have comments between options without abusing backticks.
options=(
    # Check integration tests and benchmarks as well.
    --all-targets

    --profile test

    --features eth2-cache

    # TODO(Grandine Team): Clean up `dedicated_executor` and `eth2_libp2p`.
    #                      Go back to linting all packages implicitly.
    #                      Enable `clippy::mod_module_files`.
    --no-deps
    --package ad_hoc_bench
    --package allocator
    --package arithmetic
    --package attestation_verifier
    --package benches
    --package binary_utils
    --package block_producer
    --package bls
    --package builder_api
    --package clock
    --package database
    --package deposit_tree
    --package directories
    --package eip_2335
    --package eth1
    --package eth1_api
    --package eth2_cache_utils
    --package execution_engine
    --package factory
    --package features
    --package fork_choice_control
    --package fork_choice_store
    --package genesis
    --package grandine
    --package grandine_version
    --package hashing
    --package helper_functions
    --package http_api
    --package http_api_utils
    --package interop
    --package keymanager
    --package kzg_utils
    --package liveness_tracker
    --package metrics
    --package operation_pools
    --package p2p
    --package panics
    --package predefined_chains
    --package prometheus_metrics
    --package runtime
    --package serde_utils
    --package shuffling
    --package signer
    --package slasher
    --package slashing_protection
    --package snapshot_test_utils
    --package spec_test_utils
    --package ssz
    --package ssz_derive
    --package state_cache
    --package std_ext
    --package transition_functions
    --package try_from_iterator
    --package types
    --package validator
    --package validator_key_cache

    # The `--` lets callers pass `--deny warnings` to the script.
    # Lint settings must be specified after a `--`.
    --
)

exec cargo clippy "${options[@]}" "$@"
