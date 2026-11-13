package com.yubico.yubikit.yubiotp;

import java.util.HashMap;
import java.util.Map;

/**
 * Sets individual OTP slot flags on any YubiKit slot configuration.
 *
 * <p>YubiKit exposes the tab/delay flags only on {@link YubiOtpSlotConfiguration} and
 * {@link UpdateConfiguration}, and has no setter for the "serial number visible at button
 * startup" flag, while the YubiKey (and the Windows YubiKey Personalization Tool) apply them
 * to every keyboard slot type. {@code BaseSlotConfiguration.updateFlags} is protected, so this
 * helper lives in YubiKit's package to reach it. It uses only the public flag constants from
 * {@link SlotConfiguration}; {@link UpdateConfiguration} still rejects flags that cannot be
 * changed by an update.
 */
public final class OtpFlagAccess {
  private static final Map<String, SlotConfiguration.Flag> FLAGS = new HashMap<>();

  // Explicit keys (not Flag.getFeatureName()) so minification cannot change them.
  static {
    FLAGS.put("TKTFLAG_TAB_FIRST", SlotConfiguration.TKTFLAG_TAB_FIRST);
    FLAGS.put("TKTFLAG_APPEND_TAB1", SlotConfiguration.TKTFLAG_APPEND_TAB1);
    FLAGS.put("TKTFLAG_APPEND_TAB2", SlotConfiguration.TKTFLAG_APPEND_TAB2);
    FLAGS.put("TKTFLAG_APPEND_DELAY1", SlotConfiguration.TKTFLAG_APPEND_DELAY1);
    FLAGS.put("TKTFLAG_APPEND_DELAY2", SlotConfiguration.TKTFLAG_APPEND_DELAY2);
    FLAGS.put("TKTFLAG_APPEND_CR", SlotConfiguration.TKTFLAG_APPEND_CR);
    FLAGS.put("CFGFLAG_SEND_REF", SlotConfiguration.CFGFLAG_SEND_REF);
    FLAGS.put("CFGFLAG_PACING_10MS", SlotConfiguration.CFGFLAG_PACING_10MS);
    FLAGS.put("CFGFLAG_PACING_20MS", SlotConfiguration.CFGFLAG_PACING_20MS);
    FLAGS.put("EXTFLAG_SERIAL_BTN_VISIBLE", SlotConfiguration.EXTFLAG_SERIAL_BTN_VISIBLE);
    FLAGS.put("EXTFLAG_SERIAL_USB_VISIBLE", SlotConfiguration.EXTFLAG_SERIAL_USB_VISIBLE);
    FLAGS.put("EXTFLAG_SERIAL_API_VISIBLE", SlotConfiguration.EXTFLAG_SERIAL_API_VISIBLE);
    FLAGS.put("EXTFLAG_USE_NUMERIC_KEYPAD", SlotConfiguration.EXTFLAG_USE_NUMERIC_KEYPAD);
    FLAGS.put("EXTFLAG_FAST_TRIG", SlotConfiguration.EXTFLAG_FAST_TRIG);
    FLAGS.put("EXTFLAG_ALLOW_UPDATE", SlotConfiguration.EXTFLAG_ALLOW_UPDATE);
    FLAGS.put("EXTFLAG_LED_INV", SlotConfiguration.EXTFLAG_LED_INV);
  }

  private OtpFlagAccess() {}

  /**
   * Sets or clears a flag.
   *
   * @param config a YubiKit slot configuration (any concrete type)
   * @param name the flag name as defined by YubiKit, e.g. {@code TKTFLAG_APPEND_CR}
   * @param value whether the flag is set
   */
  public static void set(SlotConfiguration config, String name, boolean value) {
    SlotConfiguration.Flag flag = FLAGS.get(name);
    if (flag == null) {
      throw new IllegalArgumentException("Unknown OTP flag " + name);
    }
    ((BaseSlotConfiguration<?>) config).updateFlags(flag, value);
  }
}
