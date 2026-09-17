package pl.seniorshield.app

import androidx.annotation.ColorRes
import androidx.annotation.StringRes

/** Why a domain was blocked, and how dangerous it is for the user. */
enum class Category(
    val key: String,
    @StringRes val nameRes: Int,
    @StringRes val ratingRes: Int,
    @StringRes val descriptionRes: Int,
    @ColorRes val colorRes: Int,
) {
    ADS("ads", R.string.cat_ads, R.string.rating_low, R.string.desc_ads, R.color.risk_low),
    TRACKING("tracking", R.string.cat_tracking, R.string.rating_medium, R.string.desc_tracking, R.color.risk_medium),
    SCAM("scam", R.string.cat_scam, R.string.rating_high, R.string.desc_scam, R.color.risk_high),

    /** Not on the bundled list, but the upstream ad-filtering resolver blocked it. */
    FILTER("filter", R.string.cat_filter, R.string.rating_medium, R.string.desc_filter, R.color.risk_medium);

    companion object {
        fun fromKey(key: String?): Category? = entries.firstOrNull { it.key == key }
    }
}
