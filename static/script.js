// Search the products currently rendered on the page as the user types.
const searchInput = document.getElementById("productSearch");
const productCards = Array.from(document.querySelectorAll(".product-column"));
const noResults = document.getElementById("noResults");
const searchStatus = document.getElementById("searchStatus");
const isProductListing = Boolean(document.getElementById("products"));

function filterProducts(query) {
    const searchTerm = query.trim().toLowerCase();
    let visibleCount = 0;

    productCards.forEach((card) => {
        const productCard = card.closest(".product-card");
        const productName = productCard.querySelector("h2, h3").textContent.toLowerCase();
        const searchableText = isProductListing
            ? productName
            : `${productName} ${card.dataset.category.toLowerCase()}`;
        const matches = searchableText.includes(searchTerm);
        card.classList.toggle("d-none", !matches);
        if (matches) visibleCount += 1;
    });

    if (noResults) noResults.classList.toggle("d-none", visibleCount > 0);
    if (searchStatus) {
        searchStatus.textContent = searchTerm
            ? `${visibleCount} ${visibleCount === 1 ? "product" : "products"} found`
            : "";
    }
}

if (searchInput) {
    searchInput.addEventListener("input", () => filterProducts(searchInput.value));
}

// Category cards on the homepage filter the featured products.
document.querySelectorAll("[data-category-link]").forEach((link) => {
    link.addEventListener("click", () => {
        if (!searchInput) return;
        searchInput.value = link.dataset.categoryLink;
        filterProducts(searchInput.value);
    });
});

function resetSearch() {
    if (!searchInput) return;
    searchInput.value = "";
    filterProducts("");
}

document.getElementById("clearSearch")?.addEventListener("click", resetSearch);
document.getElementById("resetSearch")?.addEventListener("click", resetSearch);
