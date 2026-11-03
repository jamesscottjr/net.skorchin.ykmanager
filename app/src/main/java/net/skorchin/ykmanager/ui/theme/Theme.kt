package net.skorchin.ykmanager.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val YubicoGreen = Color(0xFF4C8C27)
private val YubicoGreenDark = Color(0xFF9BD469)

private val LightColors = lightColorScheme(
    primary = YubicoGreen,
    onPrimary = Color.White,
)

private val DarkColors = darkColorScheme(
    primary = YubicoGreenDark,
)

@Composable
fun YkManagerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
