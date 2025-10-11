from playwright.sync_api import sync_playwright
import time

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    unique_username = f"testuser_{int(time.time())}"

    # Register
    page.goto("http://localhost:5004/signup", timeout=60000)
    page.wait_for_load_state("networkidle")
    page.get_by_label("Username").fill(unique_username)
    page.get_by_label("Password").fill("password")
    with page.expect_navigation():
        page.get_by_role("button", name="Create Account").click()
    assert page.url == "http://localhost:5004/~"
    print(f"Successfully registered user: {unique_username}")

    # Go to notes page
    page.goto("http://localhost:5004/notes")
    page.wait_for_selector("#notesContainer")

    # Create a new note
    page.locator("#addNoteBtn").click()
    page.get_by_placeholder("What's on your mind?").fill("This is a test note to be archived.")
    page.get_by_role("button", name="Save").click()

    # Archive the note
    page.wait_for_selector(".note-card")
    page.hover(".note-card")
    page.locator(".archive-icon").click()

    # Go to archive page by clicking the header link
    page.locator("#headerTitle a").click()
    page.wait_for_selector(".note-card")

    page.screenshot(path="jules-scratch/verification/archive_page_refactor.png")
    print("Successfully took screenshot of archive page.")

    # Go back to notes page
    page.locator("#headerTitle a").click()
    page.wait_for_selector("#addNoteBtn")

    page.screenshot(path="jules-scratch/verification/notes_page_refactor.png")
    print("Successfully took screenshot of notes page.")


    browser.close()

with sync_playwright() as playwright:
    run(playwright)