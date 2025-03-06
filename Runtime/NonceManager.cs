using System;
using System.Collections.Generic;
using UnityEngine;

namespace Network_Discovery
{
    public class NonceManager
    {
        private readonly Dictionary<string, long> usedNonces = new(); // Nonce → Timestamp
        private readonly long nonceExpirationTime = 30; // (seconds) Nonces older than 30s will be removed
        private long lastCleanupTime = 0;               // Will store a Unix timestamp
        private readonly long cleanupInterval = 60;     // (seconds) Cleanup runs every 60s

        /// <summary>
        /// Checks if the nonce is valid (not reused and recent).
        /// If valid, stores it and returns true. Otherwise, returns false.
        /// </summary>
        public bool ValidateAndStoreNonce(string nonce, long timestamp)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Step 1: Remove expired nonces periodically
            if (now - lastCleanupTime > cleanupInterval)
            {
                CleanupOldNonces(now);
                lastCleanupTime = now;
            }

            // Step 2: Reject if nonce is already used
            if (usedNonces.ContainsKey(nonce))
            {
                Debug.Log("[Authentication] Rejected reused nonce.");
                return false;
            }

            // Step 3: Reject if timestamp is too old
            if (now - timestamp > nonceExpirationTime)
            {
                Debug.Log("[Authentication] Rejected expired nonce.");
                return false;
            }

            // Step 4: Store the nonce
            usedNonces[nonce] = timestamp;
            return true;
        }

        /// <summary>
        /// Removes nonces that are older than `nonceExpirationTime`.
        /// </summary>
        private void CleanupOldNonces(long now)
        {
            List<string> expiredNonces = new();
            foreach (var kvp in usedNonces)
            {
                if (now - kvp.Value > nonceExpirationTime)
                {
                    expiredNonces.Add(kvp.Key);
                }
            }

            foreach (var nonce in expiredNonces)
            {
                usedNonces.Remove(nonce);
            }

            //Debug.Log($"[Authentication] Cleaned up {expiredNonces.Count} old nonces.");
        }
    }
}
