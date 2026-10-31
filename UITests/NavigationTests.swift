import XCTest

final class NavigationTests: XCTestCase {
    func testExperimentalAppLaunchAndNavigation() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.navigationBars["Home"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["Signing and device services are disabled pending validation."].exists)
        capture("Home", app: app)
        app.tabBars.buttons["Library"].tap()
        XCTAssertTrue(app.navigationBars["IPA Library"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Import from Files"].exists)
        capture("IPA Library", app: app)
        app.tabBars.buttons["Signing"].tap()
        XCTAssertTrue(app.navigationBars["Signing Center"].waitForExistence(timeout: 5))
        capture("Signing Center", app: app)
        app.tabBars.buttons["Diagnostics"].tap()
        XCTAssertTrue(app.navigationBars["Diagnostics"].waitForExistence(timeout: 5))
        capture("Diagnostics", app: app)
        app.tabBars.buttons["My Apps"].tap()
        XCTAssertTrue(app.navigationBars["My Apps"].waitForExistence(timeout: 5))
    }
    private func capture(_ name: String, app: XCUIApplication) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
