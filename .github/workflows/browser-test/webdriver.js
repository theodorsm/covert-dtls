/*
 *  Copyright (c) 2022 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
const os = require('os');
const path = require('path');

const webdriver = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const firefox = require('selenium-webdriver/firefox');
const safari = require('selenium-webdriver/safari');

const puppeteerBrowsers = require('@puppeteer/browsers');

async function download(browser, version, cacheDir, platform) {
  const buildId = await puppeteerBrowsers
    .resolveBuildId(browser, platform, version);
  await puppeteerBrowsers.install({
    browser,
    buildId,
    cacheDir,
    platform
  });
  return buildId;
}
const cacheDir = path.join(process.cwd(), 'browsers');

if (os.platform() === 'win32') {
  process.env.PATH += ';' + process.cwd() + '\\node_modules\\chromedriver\\lib\\chromedriver\\';
  process.env.PATH += ';' + process.cwd() + '\\node_modules\\geckodriver';
} else {
  process.env.PATH += ':node_modules/.bin';
}

function mapVersion(browser, version) {
  const versionMap = {
    chrome: {
      unstable: 'canary',
    },
    firefox: {
      unstable: 'nightly',
    }
  };
  return (versionMap[browser] || {})[version] || version;
}

async function buildDriver(browser = process.env.BROWSER || 'chrome', options = { version: process.env.BVER }) {
  const version = mapVersion(options.version);
  const platform = puppeteerBrowsers.detectBrowserPlatform();

  const buildId = await download(browser, version || 'stable',
    cacheDir, platform);

  // Chrome options.
  const chromeOptions = new chrome.Options()
    .addArguments('no-sandbox')
    .addArguments('allow-insecure-localhost')
    .addArguments('use-fake-device-for-media-stream')
    .addArguments('allow-file-access-from-files');
  if (options.chromeFlags) {
    options.chromeFlags.forEach((flag) => chromeOptions.addArguments(flag));
  }
  if (options.chromepath) {
    chromeOptions.setChromeBinaryPath(options.chromepath);
  } else {
    chromeOptions.setChromeBinaryPath(puppeteerBrowsers
      .computeExecutablePath({ browser, buildId, cacheDir, platform }));
  }

  if (!options.devices || options.headless) {
    // GUM doesn't work in headless mode so we need this. See
    // https://bugs.chromium.org/p/chromium/issues/detail?id=776649
    chromeOptions.addArguments('use-fake-ui-for-media-stream');
  } else {
    // see https://bugs.chromium.org/p/chromium/issues/detail?id=459532#c22
    const domain = 'https://' + (options.devices.domain || 'localhost') + ':' + (options.devices.port || 443) + ',*';
    const exceptions = {
      media_stream_mic: {},
      media_stream_camera: {},
    };

    exceptions.media_stream_mic[domain] = {
      last_used: Date.now(),
      setting: options.devices.audio ? 1 : 2 // 0: ask, 1: allow, 2: denied
    };
    exceptions.media_stream_camera[domain] = {
      last_used: Date.now(),
      setting: options.devices.video ? 1 : 2
    };

    chromeOptions.setUserPreferences({
      profile: {
        content_settings: {
          exceptions: exceptions
        }
      }
    });
  }

  // Safari options.
  const safariOptions = new safari.Options();
  safariOptions.setTechnologyPreview(version === 'unstable');

  // Firefox options.
  const firefoxOptions = new firefox.Options();
  let firefoxPath = firefox.Channel.RELEASE;
  if (options.firefoxpath) {
    firefoxPath = options.firefoxpath;
  } else {
    firefoxPath = puppeteerBrowsers
      .computeExecutablePath({ browser, buildId, cacheDir, platform });
  }
  if (options.headless) {
    firefoxOptions.addArguments('-headless');
  }
  firefoxOptions.setBinary(firefoxPath);
  firefoxOptions.setPreference('media.navigator.streams.fake', true);
  firefoxOptions.setPreference('media.navigator.permission.disabled', true);

  const driver = new webdriver.Builder()
    .setChromeOptions(chromeOptions)
    .setSafariOptions(safariOptions)
    .setFirefoxOptions(firefoxOptions)
    .forBrowser(browser)
    .setChromeService(
      new chrome.ServiceBuilder().addArguments('--disable-build-check')
    );

  if (browser === 'firefox') {
    driver.getCapabilities().set('marionette', true);
    driver.getCapabilities().set('acceptInsecureCerts', true);
  }
  return driver.build();
}

module.exports = {
  buildDriver,
};
