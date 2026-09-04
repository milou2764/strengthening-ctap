package com.example.ctapwallet

import android.content.Context

/**
 * Trust store for enrolled client public keys, each with a friendly device name
 * and an enrollment time.
 *
 * Enrolled keys expire [KEY_TTL_MS] after enrollment (90 days): an expired
 * client is treated exactly like one that was never enrolled -- its assertion
 * no longer verifies and the session is aborted -- and the user simply
 * re-enrolls it, which refreshes the timestamp. This bounds the lifetime of a
 * trust relationship the user may have forgotten about (Section "Device
 * Management and Revocation" of the paper).
 *
 * Storage is a SharedPreferences set of "base64Key\tname\tenrolledAtMillis"
 * entries; entries from older builds that carry no timestamp are dropped on
 * first contact (their age is unknown, so the secure default is to expire
 * them). A production authenticator would keep this in secure storage with
 * richer metadata.
 */
class ClientTrustStore(context: Context) {

    data class Entry(
        val publicKeyB64: String,
        val name: String,
        val enrolledAtMillis: Long,
    ) {
        val expiresAtMillis: Long get() = enrolledAtMillis + KEY_TTL_MS
        fun isExpired(now: Long = System.currentTimeMillis()): Boolean =
            now >= expiresAtMillis
        fun daysLeft(now: Long = System.currentTimeMillis()): Long =
            (expiresAtMillis - now) / DAY_MS
    }

    private val prefs =
        context.getSharedPreferences("ctap_trust", Context.MODE_PRIVATE)

    fun addClient(publicKeyB64: String, name: String) {
        val entries = raw().toMutableSet()
        entries.removeAll { it.substringBefore('\t') == publicKeyB64 }
        entries.add("$publicKeyB64\t$name\t${System.currentTimeMillis()}")
        prefs.edit().putStringSet(KEY_CLIENTS, entries).apply()
    }

    fun removeClient(publicKeyB64: String) {
        val entries = raw().toMutableSet()
        entries.removeAll { it.substringBefore('\t') == publicKeyB64 }
        prefs.edit().putStringSet(KEY_CLIENTS, entries).apply()
    }

    /** Every stored entry, expired ones included (for display). */
    fun enrolled(): List<Entry> {
        purgeMalformed()
        return raw().mapNotNull { parse(it) }
    }

    /**
     * The entries assertions may verify against: enrolled and not expired.
     * Expired entries are purged from storage as a side effect, so an expired
     * client also disappears from the UI list once it has been refused.
     */
    fun valid(): List<Entry> {
        val now = System.currentTimeMillis()
        val all = raw()
        val (live, stale) = all.partition { parse(it)?.isExpired(now) == false }
        if (stale.isNotEmpty()) {
            prefs.edit().putStringSet(KEY_CLIENTS, live.toSet()).apply()
        }
        return live.mapNotNull { parse(it) }
    }

    fun count(): Int = enrolled().size

    private fun parse(s: String): Entry? {
        val parts = s.split('\t')
        if (parts.size < 3) return null   // legacy, no timestamp: expire
        val at = parts[2].toLongOrNull() ?: return null
        return Entry(parts[0], parts[1], at)
    }

    private fun purgeMalformed() {
        val all = raw()
        val ok = all.filter { parse(it) != null }
        if (ok.size != all.size) {
            prefs.edit().putStringSet(KEY_CLIENTS, ok.toSet()).apply()
        }
    }

    private fun raw(): Set<String> =
        prefs.getStringSet(KEY_CLIENTS, emptySet()) ?: emptySet()

    companion object {
        const val KEY_TTL_MS = 90L * 24 * 60 * 60 * 1000   // 90 days
        private const val DAY_MS = 24 * 60 * 60 * 1000L
        private const val KEY_CLIENTS = "clients"
    }
}
