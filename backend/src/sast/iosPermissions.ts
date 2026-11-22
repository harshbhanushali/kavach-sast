/**
 * Privacy-permission catalogue for Info.plist usage-description keys.
 *
 * Every NS*UsageDescription key used to be reported as "dangerous" with one
 * generic sentence, which made a camera prompt and a Bluetooth prompt
 * indistinguishable. Each known key now carries what it grants and how sensitive
 * that is; unknown keys keep a conservative default.
 */
import { dictGet } from './plist.ts';
import type { PlistValue } from './plist.ts';

type Entry = { label: string; level: 'dangerous' | 'normal'; grants: string };

const CATALOGUE: Record<string, Entry> = {
  NSCameraUsageDescription: { label: 'Camera', level: 'dangerous', grants: 'Capture photos and video, and read the live camera feed.' },
  NSMicrophoneUsageDescription: { label: 'Microphone', level: 'dangerous', grants: 'Record audio, including while the app is in use.' },
  NSPhotoLibraryUsageDescription: { label: 'Photo library (read)', level: 'dangerous', grants: 'Read every photo and video, with location metadata.' },
  NSPhotoLibraryAddUsageDescription: { label: 'Photo library (add)', level: 'normal', grants: 'Save images to the photo library. No read access.' },
  NSLocationWhenInUseUsageDescription: { label: 'Location (while in use)', level: 'dangerous', grants: 'Precise location while the app is on screen.' },
  NSLocationAlwaysAndWhenInUseUsageDescription: { label: 'Location (always)', level: 'dangerous', grants: 'Precise location in the background, continuously.' },
  NSLocationAlwaysUsageDescription: { label: 'Location (always, legacy)', level: 'dangerous', grants: 'Background location on older iOS versions.' },
  NSLocationUsageDescription: { label: 'Location (legacy)', level: 'dangerous', grants: 'Location on older iOS versions.' },
  NSContactsUsageDescription: { label: 'Contacts', level: 'dangerous', grants: 'Read the address book: names, numbers, emails.' },
  NSCalendarsUsageDescription: { label: 'Calendars', level: 'dangerous', grants: 'Read and write calendar events.' },
  NSCalendarsFullAccessUsageDescription: { label: 'Calendars (full)', level: 'dangerous', grants: 'Read and write every calendar event.' },
  NSRemindersUsageDescription: { label: 'Reminders', level: 'dangerous', grants: 'Read and write reminders.' },
  NSHealthShareUsageDescription: { label: 'Health (read)', level: 'dangerous', grants: 'Read health and fitness records.' },
  NSHealthUpdateUsageDescription: { label: 'Health (write)', level: 'dangerous', grants: 'Write health and fitness records.' },
  NSMotionUsageDescription: { label: 'Motion & fitness', level: 'normal', grants: 'Read accelerometer, gyroscope and pedometer data.' },
  NSFaceIDUsageDescription: { label: 'Face ID', level: 'normal', grants: 'Authenticate with Face ID. The app never receives the biometric data.' },
  NSBluetoothAlwaysUsageDescription: { label: 'Bluetooth', level: 'dangerous', grants: 'Discover and connect to nearby Bluetooth devices.' },
  NSBluetoothPeripheralUsageDescription: { label: 'Bluetooth (legacy)', level: 'dangerous', grants: 'Act as a Bluetooth peripheral on older iOS versions.' },
  NSSpeechRecognitionUsageDescription: { label: 'Speech recognition', level: 'dangerous', grants: 'Send audio to Apple for transcription.' },
  NSUserTrackingUsageDescription: { label: 'App tracking', level: 'dangerous', grants: 'Read the advertising identifier and track across other companies’ apps.' },
  NSLocalNetworkUsageDescription: { label: 'Local network', level: 'dangerous', grants: 'Discover and talk to devices on the local network.' },
  NSNearbyInteractionUsageDescription: { label: 'Nearby interaction', level: 'normal', grants: 'Measure distance to nearby devices with ultra-wideband.' },
  NFCReaderUsageDescription: { label: 'NFC', level: 'normal', grants: 'Read NFC tags.' },
  NSSiriUsageDescription: { label: 'Siri', level: 'normal', grants: 'Handle Siri requests and shortcuts.' },
  NSHomeKitUsageDescription: { label: 'HomeKit', level: 'dangerous', grants: 'Read and control the user’s smart-home accessories.' },
  NSAppleMusicUsageDescription: { label: 'Media library', level: 'normal', grants: 'Read the media library.' },
  NSFileProviderDomainUsageDescription: { label: 'File provider', level: 'normal', grants: 'Expose files to the Files app.' },
  NSFileProviderPresenceUsageDescription: { label: 'File provider presence', level: 'normal', grants: 'Show who else is viewing a file.' },
  NSPhotoLibraryUsage: { label: 'Photo library', level: 'dangerous', grants: 'Read photos.' },
};

/** A purpose string this short cannot tell a user why the app is asking. */
const VAGUE = 12;

export function describePermission(
  key: string,
  info: PlistValue,
): { name: string; level: string; description: string } {
  const purpose = dictGet(info, key);
  const text = typeof purpose === 'string' ? purpose.trim() : '';
  const entry = CATALOGUE[key];

  const base = entry
    ? `${entry.label}. ${entry.grants}`
    : 'Declares a privacy-sensitive capability; iOS prompts the user with the purpose string at first use.';
  const shown = text ? ` Prompt shown to the user: “${text}”.` : ' No purpose string is set; the app will be rejected at review or crash on first use.';
  const vague = text && text.length < VAGUE ? ' The purpose string is too short to explain the request.' : '';

  return { name: key, level: entry?.level ?? 'dangerous', description: `${base}${shown}${vague}` };
}
