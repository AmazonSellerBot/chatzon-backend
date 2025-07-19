def get_suggestions(action_type: str, payload: dict):
    suggestions = []

    if action_type == "price_update":
        price = payload.get("price", 0)
        original_price = payload.get("original_price", None)
        asin = payload.get("asin", "unknown")

        if price <= 0:
            suggestions.append("⚠️ Price is $0 or less — listing may be suppressed.")
        elif original_price and abs(price - original_price) / original_price > 0.2:
            suggestions.append("💡 Price changed by more than 20%. This may trigger Buy Box suppression.")

    elif action_type == "title_update":
        title = payload.get("title", "")
        if len(title) > 200:
            suggestions.append("✂️ Title is longer than 200 characters. Consider shortening for mobile visibility.")
        if any(word in title.lower() for word in ["best", "cheapest", "guaranteed"]):
            suggestions.append("🛑 Avoid prohibited words like 'best' or 'guaranteed' — may violate Amazon's TOS.")

    elif action_type == "keywords_update":
        keywords = payload.get("keywords", [])
        if not keywords or all(not k.strip() for k in keywords):
            suggestions.append("💡 You didn’t include any backend keywords. Want help generating some?")
        if any(len(k) > 50 for k in keywords):
            suggestions.append("⚠️ One or more keywords is over 50 characters — shorten to avoid indexing issues.")

    elif action_type == "bullet_update":
        bullets = payload.get("bullets", [])
        if len(bullets) < 3:
            suggestions.append("💡 Listings with at least 3 bullet points tend to convert better.")
        for b in bullets:
            if len(b.strip()) < 20:
                suggestions.append("📝 Some bullet points are too short. Aim for at least 20–30 characters.")

    return suggestions
