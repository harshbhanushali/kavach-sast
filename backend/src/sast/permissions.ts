/**
 * Android permission knowledge base.
 *
 * A report that lists `android.permission.RECORD_AUDIO` and stops has told the
 * reader nothing they could not get from `aapt`. Pairing each permission with its
 * protection level and a plain description is what makes the permission table
 * reviewable rather than decorative.
 *
 * Protection levels follow AOSP's `frameworks/base/core/res/AndroidManifest.xml`.
 * Only permissions worth a reviewer's attention are described; anything not
 * listed is reported with its name and an unknown level, never silently dropped.
 */

export type ProtectionLevel = 'normal' | 'dangerous' | 'signature' | 'unknown';

export type PermissionInfo = {
  name: string;
  level: ProtectionLevel;
  /** What the permission lets the app do, in one line. */
  description: string;
};

const KB: Record<string, [ProtectionLevel, string]> = {
  // --- location ---
  ACCESS_FINE_LOCATION: ['dangerous', 'Read precise GPS location.'],
  ACCESS_COARSE_LOCATION: ['dangerous', 'Read approximate network-based location.'],
  ACCESS_BACKGROUND_LOCATION: ['dangerous', 'Read location while the app is in the background.'],
  ACCESS_MEDIA_LOCATION: ['dangerous', 'Read the geographic coordinates embedded in the user\'s photos.'],

  // --- identity and accounts ---
  READ_PHONE_STATE: ['dangerous', 'Read phone number, cellular network info, and call status.'],
  READ_PHONE_NUMBERS: ['dangerous', 'Read the device\'s own phone numbers.'],
  GET_ACCOUNTS: ['dangerous', 'List the accounts configured on the device.'],
  READ_PRIVILEGED_PHONE_STATE: ['signature', 'Read privileged device identifiers such as IMEI.'],

  // --- messaging ---
  READ_SMS: ['dangerous', 'Read the user\'s SMS messages, including one-time passcodes.'],
  RECEIVE_SMS: ['dangerous', 'Intercept incoming SMS as they arrive.'],
  SEND_SMS: ['dangerous', 'Send SMS messages, which can cost the user money.'],
  RECEIVE_MMS: ['dangerous', 'Intercept incoming MMS messages.'],
  READ_CALL_LOG: ['dangerous', 'Read the history of calls placed and received.'],
  WRITE_CALL_LOG: ['dangerous', 'Modify the call history.'],
  PROCESS_OUTGOING_CALLS: ['dangerous', 'Observe and reroute outgoing calls.'],
  CALL_PHONE: ['dangerous', 'Place calls without the dialer confirming with the user.'],
  ANSWER_PHONE_CALLS: ['dangerous', 'Answer incoming calls programmatically.'],

  // --- contacts and calendar ---
  READ_CONTACTS: ['dangerous', 'Read the user\'s address book.'],
  WRITE_CONTACTS: ['dangerous', 'Modify the user\'s address book.'],
  READ_CALENDAR: ['dangerous', 'Read calendar events.'],
  WRITE_CALENDAR: ['dangerous', 'Add or change calendar events.'],

  // --- sensors and capture ---
  CAMERA: ['dangerous', 'Take pictures and record video.'],
  RECORD_AUDIO: ['dangerous', 'Record audio from the microphone.'],
  BODY_SENSORS: ['dangerous', 'Read heart rate and other body sensors.'],
  ACTIVITY_RECOGNITION: ['dangerous', 'Infer physical activity such as walking or driving.'],

  // --- storage ---
  READ_EXTERNAL_STORAGE: ['dangerous', 'Read files in shared storage.'],
  WRITE_EXTERNAL_STORAGE: ['dangerous', 'Write files to shared storage.'],
  MANAGE_EXTERNAL_STORAGE: ['dangerous', 'Read and write all shared storage, bypassing scoped storage.'],
  READ_MEDIA_IMAGES: ['dangerous', 'Read the user\'s photos.'],
  READ_MEDIA_VIDEO: ['dangerous', 'Read the user\'s videos.'],
  READ_MEDIA_AUDIO: ['dangerous', 'Read the user\'s audio files.'],

  // --- high-impact capabilities ---
  SYSTEM_ALERT_WINDOW: ['signature', 'Draw over other apps. This is the overlay capability used for tapjacking.'],
  BIND_ACCESSIBILITY_SERVICE: ['signature', 'Read screen content and inject input across every app. The most powerful permission on the platform.'],
  REQUEST_INSTALL_PACKAGES: ['signature', 'Prompt the user to install other APKs.'],
  QUERY_ALL_PACKAGES: ['normal', 'See every installed app, bypassing package-visibility filtering.'],
  PACKAGE_USAGE_STATS: ['signature', 'Read which apps the user opens and for how long.'],
  BIND_DEVICE_ADMIN: ['signature', 'Act as a device administrator.'],
  BIND_NOTIFICATION_LISTENER_SERVICE: ['signature', 'Read the content of every notification, including OTP codes.'],
  WRITE_SECURE_SETTINGS: ['signature', 'Change protected system settings.'],
  REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: ['normal', 'Run unrestricted in the background.'],

  // --- ordinary ---
  INTERNET: ['normal', 'Open network sockets.'],
  ACCESS_NETWORK_STATE: ['normal', 'Read connectivity state.'],
  ACCESS_WIFI_STATE: ['normal', 'Read Wi-Fi state, including the connected SSID.'],
  CHANGE_WIFI_STATE: ['normal', 'Connect to and disconnect from Wi-Fi networks.'],
  BLUETOOTH: ['normal', 'Connect to paired Bluetooth devices.'],
  BLUETOOTH_CONNECT: ['dangerous', 'Connect to paired Bluetooth devices (Android 12+).'],
  BLUETOOTH_SCAN: ['dangerous', 'Scan for nearby Bluetooth devices, which can infer location.'],
  NEARBY_WIFI_DEVICES: ['dangerous', 'Discover nearby Wi-Fi devices.'],
  POST_NOTIFICATIONS: ['dangerous', 'Show notifications.'],
  VIBRATE: ['normal', 'Use the vibrator.'],
  WAKE_LOCK: ['normal', 'Keep the device awake.'],
  FOREGROUND_SERVICE: ['normal', 'Run a foreground service.'],
  RECEIVE_BOOT_COMPLETED: ['normal', 'Start automatically after the device boots.'],
  USE_BIOMETRIC: ['normal', 'Authenticate the user with biometrics.'],
  USE_FINGERPRINT: ['normal', 'Authenticate the user with a fingerprint (deprecated).'],
  CHANGE_NETWORK_STATE: ['normal', 'Change network connectivity state.'],
  MODIFY_AUDIO_SETTINGS: ['normal', 'Change global audio settings.'],
  READ_SYNC_SETTINGS: ['normal', 'Read sync settings.'],
  WRITE_SYNC_SETTINGS: ['normal', 'Change sync settings.'],
  SET_WALLPAPER: ['normal', 'Change the wallpaper.'],
  EXPAND_STATUS_BAR: ['normal', 'Expand or collapse the status bar.'],
  DISABLE_KEYGUARD: ['normal', 'Dismiss the lock screen.'],
  GET_TASKS: ['normal', 'Read information about running tasks (deprecated).'],
  KILL_BACKGROUND_PROCESSES: ['normal', 'Kill other apps\' background processes.'],
  SCHEDULE_EXACT_ALARM: ['normal', 'Schedule alarms that fire at an exact time.'],
  USE_EXACT_ALARM: ['normal', 'Schedule exact alarms without a user prompt.'],
  CREDENTIAL_MANAGER_QUERY_CANDIDATE_CREDENTIALS: ['normal', 'Query available credentials.'],
};

export function describePermission(name: string): PermissionInfo {
  const short = name.replace(/^android\.permission\./, '').replace(/^com\.android\.[a-z]+\./, '');
  const entry = KB[short];
  if (entry) return { name, level: entry[0], description: entry[1] };

  // Vendor and library permissions are common and mostly benign; say so rather
  // than pretending to know, and never omit the row.
  const custom = !name.startsWith('android.permission.');
  return {
    name,
    level: 'unknown',
    description: custom
      ? 'Custom or third-party permission; its protection level is defined by the app or library that declares it.'
      : 'Platform permission not in this knowledge base.',
  };
}

export function describeAll(names: string[]): PermissionInfo[] {
  const order: Record<ProtectionLevel, number> = { dangerous: 0, signature: 1, unknown: 2, normal: 3 };
  return names
    .map(describePermission)
    .sort((a, b) => order[a.level] - order[b.level] || a.name.localeCompare(b.name));
}
