// Gives slow buttons (ones that wait on Google Play) immediate feedback: a button with
// data-busy="Looking up…" switches to that text and disables itself once its form submits.
// Disabled a tick later on purpose - disabling it during the submit event would drop the
// button's own name/value from the submitted form.
document.addEventListener("submit", (event) => {
    const button = event.submitter;
    if (!button || !button.dataset.busy) return;
    setTimeout(() => {
        button.disabled = true;
        button.textContent = button.dataset.busy;
    }, 0);
});
