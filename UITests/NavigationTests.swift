import XCTest

final class NavigationTests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }
    func testExperimentalAppLaunchAndNavigation() {
        let app = XCUIApplication()
        app.launch()
        require(app.navigationBars["Home"].waitForExistence(timeout: 15), "Home must appear", app: app)
        require(app.staticTexts["Signing and device services are disabled pending validation."].exists, "Experimental gate must be visible", app: app)
        capture("Home", app: app)
        navigate("Library", title: "IPA Library", app: app)
        require(app.buttons["Import from Files"].waitForExistence(timeout: 15), "Real import control must appear", app: app)
        capture("IPA Library", app: app)
        navigate("Signing", title: "Signing Center", app: app)
        capture("Signing Center", app: app)
        navigate("Diagnostics", title: "Diagnostics", app: app)
        capture("Diagnostics", app: app)
        navigate("My Apps", title: "My Apps", app: app)
    }
    private func navigate(_ label: String, title: String, app: XCUIApplication) {
        let button = app.tabBars.buttons[label]
        require(button.waitForExistence(timeout: 15) && button.isHittable, "Tab must be available: \(label)", app: app)
        button.tap()
        let selected = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in button.isSelected }, object: button)
        require(XCTWaiter.wait(for: [selected], timeout: 15) == .completed, "Tab selection must change: \(label)", app: app)
        require(app.navigationBars[title].waitForExistence(timeout: 15), "Destination must appear: \(title)", app: app)
    }
    private func require(_ condition: Bool, _ message: String, app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) {
        if !condition {
            // Hosted synthetic fixture content only. Never used by production diagnostics.
            let tree = String(app.debugDescription.prefix(20_000))
            print("Synthetic CI UI failure hierarchy: \(tree)")
            let attachment = XCTAttachment(string: tree)
            attachment.name = "Failed navigation hierarchy"
            attachment.lifetime = .keepAlways
            add(attachment)
            capture("Failed navigation", app: app)
        }
        XCTAssertTrue(condition, message, file: file, line: line)
    }
    private func capture(_ name: String, app: XCUIApplication) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
