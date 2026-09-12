import { theme } from 'antd';
import type { ThemeConfig } from 'antd';

// Seed Token (Global base token)
const seedToken: NonNullable<ThemeConfig['token']> = {
  colorPrimary: '#6932ff',
  colorPrimaryHover: '#c333ff',
  borderRadius: 8,
  fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
};

// Button Token
const buttonToken: NonNullable<NonNullable<ThemeConfig['components']>['Button']> = {
  controlHeightLG: 48,
  controlHeight: 40,
  controlHeightSM: 32,
  paddingInlineLG: 24,
  paddingInline: 20,
  paddingInlineSM: 16,
  borderRadiusLG: 12,
  borderRadius: 12,
  borderRadiusSM: 8,
  fontSizeLG: 16,
  fontSize: 14,
  fontSizeSM: 14,
  fontWeightStrong: 600,
};

// Input Token
const inputToken: NonNullable<NonNullable<ThemeConfig['components']>['Input']> = {
  controlHeightLG: 48,
  controlHeight: 48,
  controlHeightSM: 36,
  borderRadius: 8,
  paddingInline: 16,
  paddingInlineLG: 16,
  paddingInlineSM: 12,
  activeBorderColor: '#c333ff',
  hoverBorderColor: '#c333ff',
  activeShadow: '0 0 0 2px rgba(195, 51, 255, 0.1)',
};

// Select Token
const selectToken: NonNullable<NonNullable<ThemeConfig['components']>['Select']> = {
  controlHeightLG: 48,
  controlHeight: 48,
  controlHeightSM: 36,
  borderRadius: 8,
};

// Menu Token
const menuToken: NonNullable<NonNullable<ThemeConfig['components']>['Menu']> = {
  itemHeight: 48,
  itemBorderRadius: 12,
  subMenuItemBorderRadius: 10,
  itemPaddingInline: 16,
  itemMarginBlock: 4,
  iconSize: 20,
  iconMarginInlineEnd: 12,
  activeBarWidth: 0,
  itemBg: 'transparent',
};

// Dark mode token
const darkModeToken: NonNullable<ThemeConfig['token']> = {
  colorBgContainer: 'var(--gray-800)',
  colorBgElevated: 'var(--gray-700)',
  colorBorder: 'var(--border-default)',
  colorText: 'var(--text-primary)',
  colorTextSecondary: 'var(--text-secondary)',
};

// Light mode token
const lightModeToken: NonNullable<ThemeConfig['token']> = {
  colorBgContainer: '#ffffff',
  colorBgElevated: '#ffffff',
  colorBorder: '#eef0f2',
  colorText: 'rgba(0, 0, 0, 0.87)',
  colorTextSecondary: 'rgba(0, 0, 0, 0.6)',
};

// Export config
export const getAntdThemeConfig = (isDarkMode: boolean): ThemeConfig => ({
  algorithm: isDarkMode ? theme.darkAlgorithm : theme.defaultAlgorithm,
  token: {
    ...seedToken,
    ...(isDarkMode ? darkModeToken : lightModeToken),
  },
  components: {
    Button: buttonToken,
    Input: inputToken,
    Select: selectToken,
    Menu: menuToken,
  },
});
