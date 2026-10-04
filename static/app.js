document.addEventListener("DOMContentLoaded", () => {
    const forms = document.querySelectorAll("form[data-confirm]");
    forms.forEach(form => {
        form.addEventListener("submit", (event) => {
            const message = form.dataset.confirm || "Are you sure?";
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

    const fileInput = document.querySelector("#file");
    const fileName = document.querySelector("#file-name");
    if (fileInput && fileName) {
        fileInput.addEventListener("change", () => {
            fileName.textContent = fileInput.files.length
                ? fileInput.files[0].name
                : "No file selected";
        });
    }
});
