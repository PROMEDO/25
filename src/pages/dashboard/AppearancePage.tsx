/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import {
  ArrowRight,
  CheckCircle2,
  Edit,
  Eye,
  LayoutGrid,
  Layers,
  Palette,
  RotateCcw,
  Shapes,
  ShoppingBag,
  Store,
} from 'lucide-react';
import {
  MENU_SHAPES,
  MENU_THEMES,
  getAllowedThemesForPlan,
  getContrastInk,
  resolveMenuThemeEffectiveMode,
} from '../../utils/plans';
import { dashCardMotion, dashSectionMotion } from '../../utils/dashboardMotion';
import { useDashboard } from './DashboardContext';

type ReadyAppearanceId = 'toters' | 'theme1' | 'theme2' | 'theme3' | 'theme4';
type AppearanceEditMode = ReadyAppearanceId | 'custom' | null;

const READY_APPEARANCES: Array<{
  id: ReadyAppearanceId;
  title: string;
  icon: string;
  desc: string;
  pairedPresetId: string;
}> = [
  {
    id: 'toters',
    title: 'مظهر توترز',
    icon: '✨',
    desc: 'مظهر جاهز بتصميم توترز الكامل: بطاقة المتجر العائمة، التصنيفات المسطحة، الرفوف الأفقية، والسلة المميزة.',
    pairedPresetId: 'toters',
  },
  {
    id: 'theme1',
    title: 'مظهر 1',
    icon: '🛍️',
    desc: 'تصميم ستور نظيف (ستايل عنب): شريط علوي متكامل مع بحث سريع، بانر عريض، وشبكة بطاقات مربعة أنيقة.',
    pairedPresetId: 'theme1-enab',
  },
  {
    id: 'theme2',
    title: 'مظهر 2',
    icon: '🌙',
    desc: 'تصميم ليلي احترافي (ستايل أوربن بايت): غلاف 16:9 بشعار دائري متداخل، مربعات أقسام، وشريط عائم سفلي.',
    pairedPresetId: 'theme2-urbanbite',
  },
  {
    id: 'theme3',
    title: 'مظهر 3',
    icon: '🔥',
    desc: 'تصميم مطاعم الوجبات السريعة (ستايل سوبر تشكن): واجهة عالية التباين مع بحث فوري وبطاقات شهية واضحة.',
    pairedPresetId: 'theme3-menux',
  },
  {
    id: 'theme4',
    title: 'مظهر 4',
    icon: '⚡',
    desc: 'تصميم البوستر الجريء (ستايل كودو): ترويسة مموجة، بطاقات بحدود حادة وظل صلب، وأزرار إضافة بارزة.',
    pairedPresetId: 'theme4-kudo',
  },
];

const READY_APPEARANCE_ID_SET = new Set<string>(READY_APPEARANCES.map((a) => a.id));

export const AppearancePage: React.FC = () => {
  const prefersReducedMotion = useReducedMotion();
  const [editingMode, setEditingMode] = useState<AppearanceEditMode>(null);

  const {
    layoutDefinitions,
    resolvedPlan,
    isLayoutAllowed,
    selectedLayout,
    menuThemeMode,
    handleSelectThemeMode,
    menuThemePreset,
    handleSelectMenuTheme,
    handleUpdateCustomColors,
    menuThemeShape,
    handleSelectThemeShape,
    handleActivateCustomAppearance,
    restColor,
    restBgColor,
    handleInstantLayoutSelect,
    openUpgradeModal,
    restProjectType,
    terms,
    setActiveTab,
    openSettingsSection,
    onNavigate,
    publicPath,
    restName,
    allCategories,
    allItems,
  } = useDashboard();

  const isStore = terms.isStore || restProjectType === 'store';

  const openEditPage = (mode: Exclude<AppearanceEditMode, null>) => {
    setEditingMode(mode);
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const closeEditPage = () => {
    setEditingMode(null);
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  useEffect(() => {
    if (!editingMode || typeof window === 'undefined') return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeEditPage();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [editingMode]);

  if (isStore) {
    return (
      <div className="mp-appearance-page">
        <motion.section
          className="mp-appearance-section mp-estore-appearance-card"
          {...dashSectionMotion(prefersReducedMotion, 0)}
        >
          <div className="mp-estore-appearance-head">
            <div className="mp-estore-appearance-badge">
              <CheckCircle2 size={15} />
              <span>المظهر الأساسي المفعّل لمتجرك</span>
            </div>
            <button
              type="button"
              onClick={() => onNavigate(publicPath)}
              className="btn p s"
              style={{ fontWeight: 800, gap: '6px' }}
            >
              <Eye size={15} />
              <span>معاينة المتجر مباشرة</span>
            </button>
          </div>

          <div className="mp-estore-appearance-hero">
            <div className="mp-estore-appearance-copy">
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <Store size={20} style={{ color: 'var(--brand-ink, #34D399)' }} />
                <span style={{ fontSize: '14px', fontWeight: 800, color: 'var(--brand-ink, #e2e8f0)' }}>
                  مظهر المتجر الموحد
                </span>
              </div>
              <h2 className="mp-appearance-section-title" style={{ marginBottom: '6px', fontSize: '21px' }}>
                واجهة متجر موحّدة لـ {restName || 'متجرك'}
              </h2>
              <p style={{ margin: '0 0 14px', fontSize: '14.5px', color: 'var(--muted)', lineHeight: 1.55 }}>
                تصميم متكامل باللونين الأبيض والفحمي مع السلة والمفضلات.
              </p>
            </div>

            {/* Live Visual Mini-Mockup matching estore layout */}
            <div className="mp-estore-preview-frame" aria-hidden="true">
              <div className="mp-estore-preview-nav">
                <span className="mp-estore-preview-logo" />
                <span className="mp-estore-preview-search">
                  <i />
                </span>
                <span className="mp-estore-preview-cart" />
              </div>
              <div className="mp-estore-preview-cats">
                <span className="is-active" />
                <span />
                <span />
                <span />
              </div>
              <div className="mp-estore-preview-banner">
                <div>
                  <span className="line-lg" />
                  <span className="line-sm" />
                </div>
                <span className="cta-dot" />
              </div>
              <div className="mp-estore-preview-grid">
                {[0, 1, 2, 3].map((idx) => (
                  <div key={idx} className="mp-estore-preview-card">
                    <div className="thumb">
                      {idx === 0 && <span className="disc">-20%</span>}
                    </div>
                    <div className="meta">
                      <span className="t1" />
                      <div className="bottom">
                        <span className="price" />
                        <span className="btn-sq" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mp-estore-quick-actions">
            <button
              type="button"
              onClick={() => setActiveTab('cats')}
              className="mp-estore-quick-btn"
            >
              <Layers size={20} />
              <b style={{ fontSize: '15.5px' }}>الأقسام ({allCategories.length})</b>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('menu')}
              className="mp-estore-quick-btn"
            >
              <ShoppingBag size={20} />
              <b style={{ fontSize: '15.5px' }}>المنتجات ({allItems.length})</b>
            </button>
            <button
              type="button"
              onClick={() => openSettingsSection('identity')}
              className="mp-estore-quick-btn"
            >
              <Store size={20} />
              <b style={{ fontSize: '15.5px' }}>الهوية والشعار</b>
            </button>
          </div>
        </motion.section>
      </div>
    );
  }

  const allowedThemes = getAllowedThemesForPlan(resolvedPlan);
  const previewMode = resolveMenuThemeEffectiveMode(menuThemeMode);
  const isReadyShapeActive = READY_APPEARANCE_ID_SET.has(menuThemeShape);
  const isCustomActive = !isReadyShapeActive;
  const isCustomSelected = menuThemePreset === 'custom' && resolvedPlan.perms.customColors;
  const customBrandHex = restColor || '#10B981';
  const defaultPreviewBg = previewMode === 'dark' ? '#08100d' : '#f4f7f6';
  const customBgPreview = restBgColor || defaultPreviewBg;
  const customBgIsLight = getContrastInk(customBgPreview) === '#0f172a';
  const customSurfacePreview = customBgIsLight ? '#ffffff' : '#131d19';
  const customInkPreview = customBgIsLight ? '#0f172a' : '#f8fafc';
  const customLinePreview = customBgIsLight ? 'rgba(15, 23, 42, 0.14)' : 'rgba(255, 255, 255, 0.16)';

  const activeThemeObj = MENU_THEMES.find((t) => t.id === menuThemePreset);
  const activeColorLabel = isCustomSelected
    ? 'ألوان مخصصة'
    : activeThemeObj?.name || 'افتراضي';
  const activeLayoutObj = layoutDefinitions.find((l) => l.id === selectedLayout) || layoutDefinitions[0];
  const customShapes = MENU_SHAPES.filter((s) => !READY_APPEARANCE_ID_SET.has(s.id));
  const activeCustomShapeObj = customShapes.find((s) => s.id === menuThemeShape) || customShapes[0];

  const editingReadyMeta =
    editingMode && editingMode !== 'custom'
      ? READY_APPEARANCES.find((a) => a.id === editingMode) || null
      : null;

  const modalThemesList = MENU_THEMES.filter((t) => {
    if (t.seasonal || t.storeOnly) return false;
    if (editingMode === 'custom' && READY_APPEARANCES.some((a) => a.pairedPresetId === t.id)) {
      return false;
    }
    return true;
  }).sort((a, b) => {
    if (editingReadyMeta) {
      if (a.id === editingReadyMeta.pairedPresetId) return -1;
      if (b.id === editingReadyMeta.pairedPresetId) return 1;
    }
    return 0;
  });

  const renderModeSwitcherBar = () => {
    if (!resolvedPlan.perms.lightDarkMode) return null;
    return (
      <motion.div
        className="mp-appearance-top-bar"
        {...dashSectionMotion(prefersReducedMotion, 0)}
      >
        <div className="mp-appearance-mode-wrap">
          <h2 className="mp-appearance-section-title">
            مظهر المنيو
          </h2>
          <div className="mp-appearance-mode-tabs" role="group" aria-label="وضع المظهر">
            <button
              type="button"
              onClick={() => handleSelectThemeMode('light')}
              className={`mp-appearance-mode-btn ${menuThemeMode === 'light' ? 'active' : ''}`}
            >
              <span>فاتح</span>
              <span className="mp-mode-icon">☀️</span>
            </button>
            <button
              type="button"
              onClick={() => handleSelectThemeMode('dark')}
              className={`mp-appearance-mode-btn ${menuThemeMode === 'dark' ? 'active' : ''}`}
            >
              <span>غامق</span>
              <span className="mp-mode-icon">🌙</span>
            </button>
            <button
              type="button"
              onClick={() => handleSelectThemeMode('auto')}
              className={`mp-appearance-mode-btn ${menuThemeMode === 'auto' ? 'active' : ''}`}
            >
              <span>حسب الجهاز</span>
              <span className="mp-mode-icon">📱</span>
            </button>
          </div>
        </div>
      </motion.div>
    );
  };

  // Full-Page Edit View (when user clicks "تعديل" on a ready-made theme or Custom)
  if (editingMode) {
    const targetShape =
      editingMode !== 'custom'
        ? editingMode
        : isReadyShapeActive
        ? 'modern'
        : menuThemeShape;
    const isEditingModeAssigned =
      editingMode !== 'custom' ? menuThemeShape === editingMode : isCustomActive;

    return (
      <div className="mp-appearance-page">
        {/* Full-Page Top Navigation & Title Header */}
        <motion.div
          className="mp-appearance-section"
          {...dashSectionMotion(prefersReducedMotion, 0)}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
            padding: '14px 18px',
            borderRadius: '18px',
            border: '1px solid var(--mp-glass-border)',
            background: 'var(--mp-glass-bg)',
            backdropFilter: 'var(--mp-glass-blur)',
            WebkitBackdropFilter: 'var(--mp-glass-blur)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
            <button
              type="button"
              onClick={closeEditPage}
              className="btn s"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontWeight: 800,
                padding: '8px 14px',
                borderRadius: '999px',
              }}
            >
              <ArrowRight size={16} />
              <span>رجوع</span>
            </button>
            <div style={{ minWidth: 0 }}>
              <h2 className="mp-appearance-section-title" style={{ margin: 0, fontSize: '18px' }}>
                {editingReadyMeta
                  ? `${editingReadyMeta.icon} تعديل: ${editingReadyMeta.title}`
                  : '🎨 تعديل: مخصص'}
              </h2>
              <p className="muted" style={{ margin: '2px 0 0', fontSize: '12.5px' }}>
                {editingReadyMeta
                  ? `اختر لون المنيو المناسب مع الحفاظ على تصميم ${editingReadyMeta.title} الكامل`
                  : 'اختر لون المنيو وشكل العرض وتصميم البطاقات'}
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {!isEditingModeAssigned ? (
              <button
                type="button"
                className="btn p s"
                style={{ fontWeight: 800, borderRadius: '999px', padding: '8px 16px' }}
                onClick={() => {
                  if (editingMode !== 'custom') {
                    handleSelectThemeShape(editingMode);
                  } else {
                    handleActivateCustomAppearance();
                  }
                }}
              >
                {editingReadyMeta ? `تعيين ${editingReadyMeta.title}` : 'تعيين المظهر المخصص'}
              </button>
            ) : (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '12.5px',
                  fontWeight: 900,
                  color: '#10b981',
                  padding: '6px 12px',
                  borderRadius: '999px',
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.38)',
                }}
              >
                <CheckCircle2 size={14} />
                <span>معيّن حالياً</span>
              </span>
            )}
          </div>
        </motion.div>

        {renderModeSwitcherBar()}

        {/* Custom Mode: Product Display Layouts */}
        {editingMode === 'custom' && (
          <motion.section
            className="mp-appearance-section"
            {...dashSectionMotion(prefersReducedMotion, 0.06)}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <LayoutGrid size={20} style={{ color: 'var(--brand-ink, #34D399)', flexShrink: 0 }} />
              <h2 className="mp-appearance-section-title" style={{ margin: 0 }}>
                شكل العرض (طريقة عرض المنتجات)
              </h2>
            </div>

            <div className="mp-appearance-layouts-grid">
              {layoutDefinitions.map((lay, idx) => {
                const isSelected = selectedLayout === lay.id;
                const layoutAllowed = isLayoutAllowed(lay.id);
                const previewCount =
                  lay.id === 'grid4' ? 4 : lay.id === 'grid3' ? 3 : lay.id === 'grid' ? 2 : 2;
                return (
                  <motion.button
                    key={lay.id}
                    type="button"
                    onClick={() =>
                      handleInstantLayoutSelect(lay.id, {
                        forceShape: isReadyShapeActive ? 'modern' : undefined,
                      })
                    }
                    className={`mp-appearance-layout-card ${isSelected ? 'selected' : ''}`}
                    style={{ opacity: layoutAllowed ? 1 : 0.65 }}
                    {...dashCardMotion(prefersReducedMotion, idx, layoutAllowed ? 1 : 0.65, false, 0.08)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', gap: '6px' }}>
                      <span style={{ fontSize: '20px', lineHeight: 1 }}>{lay.icon}</span>
                      {!layoutAllowed ? (
                        <span
                          style={{
                            fontSize: '11.5px',
                            fontWeight: 800,
                            color: '#f59e0b',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          🔒 باقة أعلى
                        </span>
                      ) : isSelected ? (
                        <span
                          style={{
                            fontSize: '12px',
                            fontWeight: 900,
                            color: 'var(--brand-ink, #34D399)',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          مفعّل ✓
                        </span>
                      ) : null}
                    </div>

                    <div className={`mp-layout-mini-preview is-${lay.id}`} aria-hidden="true">
                      {Array.from({ length: previewCount }).map((_, cellIdx) => (
                        <div key={cellIdx} className="mp-layout-mini-cell">
                          <span className="mp-layout-mini-img" />
                          <span className="mp-layout-mini-lines">
                            <i />
                            <i className="short" />
                          </span>
                        </div>
                      ))}
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', width: '100%' }}>
                      <b style={{ fontSize: '14.5px', color: isSelected ? 'var(--brand-ink, #34D399)' : 'var(--ink)', lineHeight: 1.3 }}>
                        {lay.title}
                      </b>
                      <span style={{ fontSize: '11.5px', color: 'var(--muted)', lineHeight: 1.4 }}>
                        {lay.desc}
                      </span>
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </motion.section>
        )}

        {/* Menu Colors (Both Toters & Custom) */}
        <section className="mp-appearance-section">
          <motion.div
            style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}
            {...dashSectionMotion(prefersReducedMotion, 0.12)}
          >
            <Palette size={20} style={{ color: 'var(--brand-ink, #34D399)', flexShrink: 0 }} />
            <h2 className="mp-appearance-section-title" style={{ margin: 0 }}>
              لون المنيو
            </h2>
          </motion.div>

          <div className="mp-appearance-themes-grid">
            {modalThemesList.map((theme, idx) => {
              const isUnlocked = allowedThemes.some((t) => t.id === theme.id);
              const isSelected = menuThemePreset === theme.id;
              const pal = previewMode === 'dark' ? theme.darkPalette : theme.lightPalette;
              const targetOpacity = isUnlocked ? 1 : 0.62;
              const showWithInitialSection = idx < 2;

              return (
                <motion.button
                  key={theme.id}
                  type="button"
                  onClick={() =>
                    handleSelectMenuTheme(theme.id, {
                      keepCurrentShape: true,
                      forceShape: targetShape,
                    })
                  }
                  className={`mp-appearance-theme-card ${isSelected ? 'selected' : ''}`}
                  style={{
                    borderColor: isSelected ? pal.brand : undefined,
                    opacity: targetOpacity,
                  }}
                  {...dashCardMotion(
                    prefersReducedMotion,
                    showWithInitialSection ? idx : idx - 2,
                    targetOpacity,
                    !showWithInitialSection,
                    showWithInitialSection ? 0.16 : 0.05
                  )}
                >
                  <div
                    className="mp-theme-mini-preview"
                    style={{
                      background: pal.bg,
                      borderColor: pal.line,
                      position: 'relative',
                      overflow: 'hidden',
                    }}
                  >
                    <div className="mp-theme-mini-card" style={{ background: pal.surface, borderColor: pal.line }}>
                      <span className="mp-theme-mini-line" style={{ background: pal.text, width: '62%' }} />
                      <span className="mp-theme-mini-line" style={{ background: pal.muted, width: '40%', opacity: 0.6 }} />
                    </div>
                    <span className="mp-theme-mini-pill" style={{ background: pal.brand }} />
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <span style={{ width: '14px', height: '14px', borderRadius: '50%', background: pal.brand, border: '1px solid rgba(255,255,255,0.25)' }} />
                      <span style={{ width: '14px', height: '14px', borderRadius: '50%', background: pal.accent, border: '1px solid rgba(255,255,255,0.2)' }} />
                      <span style={{ width: '14px', height: '14px', borderRadius: '50%', background: pal.bg, border: '1px solid rgba(148,163,184,0.4)' }} />
                    </div>
                    <span style={{ fontSize: '12px', fontWeight: 800, color: isUnlocked ? (isSelected ? 'var(--brand-ink, #34D399)' : 'var(--muted)') : '#f59e0b' }}>
                      {!isUnlocked
                        ? '🔒 مقفل'
                        : isSelected
                        ? 'نشط ✓'
                        : previewMode === 'dark'
                        ? 'غامق'
                        : 'فاتح'}
                    </span>
                  </div>
                  <b style={{ fontSize: '15px', color: 'var(--ink)' }}>{theme.name}</b>
                </motion.button>
              );
            })}

            {/* Wide Custom Menu Colors Card */}
            <motion.div
              role="button"
              tabIndex={0}
              onClick={() =>
                handleSelectMenuTheme('custom', {
                  keepCurrentShape: true,
                  forceShape: targetShape,
                })
              }
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  handleSelectMenuTheme('custom', {
                    keepCurrentShape: true,
                    forceShape: targetShape,
                  });
                }
              }}
              className={`mp-appearance-theme-card mp-appearance-custom-theme-card ${isCustomSelected ? 'selected' : ''}`}
              style={{
                borderColor: isCustomSelected ? customBrandHex : undefined,
                opacity: resolvedPlan.perms.customColors ? 1 : 0.72,
              }}
              {...dashCardMotion(prefersReducedMotion, 2, resolvedPlan.perms.customColors ? 1 : 0.72, true, 0.1)}
            >
              <div
                className="mp-theme-mini-preview"
                style={{
                  background: customBgPreview,
                  borderColor: customLinePreview,
                }}
              >
                <div className="mp-theme-mini-card" style={{ background: customSurfacePreview, borderColor: customLinePreview }}>
                  <span className="mp-theme-mini-line" style={{ background: customInkPreview, width: '58%' }} />
                  <span className="mp-theme-mini-line" style={{ background: customBrandHex, width: '36%', opacity: 0.75 }} />
                </div>
                <span className="mp-theme-mini-pill" style={{ background: customBrandHex }} />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', gap: '8px', flexWrap: 'wrap' }}>
                <b style={{ fontSize: '15.5px', color: 'var(--ink)' }}>
                  ألوان مخصصة 🎨
                </b>
                <span style={{ fontSize: '12.5px', fontWeight: 800, color: resolvedPlan.perms.customColors ? (isCustomSelected ? 'var(--brand-ink, #34D399)' : 'var(--muted)') : '#f59e0b' }}>
                  {!resolvedPlan.perms.customColors
                    ? '🔒 باقة أعلى'
                    : isCustomSelected
                    ? 'نشط ✓'
                    : 'تخصيص حر'}
                </span>
              </div>

              <div
                className="mp-custom-color-controls"
                onClick={(e) => {
                  e.stopPropagation();
                  if (!resolvedPlan.perms.customColors) {
                    openUpgradeModal('vip');
                  }
                }}
              >
                <label className="mp-custom-color-chip">
                  <input
                    type="color"
                    disabled={!resolvedPlan.perms.customColors}
                    value={customBrandHex}
                    onChange={(e) => handleUpdateCustomColors(e.target.value, undefined, targetShape)}
                    aria-label="اللون الأساسي"
                  />
                  <div style={{ minWidth: 0 }}>
                    <span className="mp-custom-color-label">اللون الأساسي</span>
                    <span className="mp-custom-color-hex tabular-nums" dir="ltr">{customBrandHex.toUpperCase()}</span>
                  </div>
                </label>

                <label className="mp-custom-color-chip">
                  <input
                    type="color"
                    disabled={!resolvedPlan.perms.customColors}
                    value={customBgPreview}
                    onChange={(e) => handleUpdateCustomColors(undefined, e.target.value, targetShape)}
                    aria-label="لون الخلفية"
                  />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <span className="mp-custom-color-label">لون الخلفية</span>
                    <span className="mp-custom-color-hex tabular-nums" dir="ltr">
                      {restBgColor ? restBgColor.toUpperCase() : 'تلقائي'}
                    </span>
                  </div>
                  {restBgColor && resolvedPlan.perms.customColors && (
                    <button
                      type="button"
                      title="إرجاع الخلفية تلقائياً"
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        handleUpdateCustomColors(undefined, '', targetShape);
                      }}
                      style={{
                        width: '24px',
                        height: '24px',
                        borderRadius: '999px',
                        border: '1px solid var(--mp-glass-border, var(--line))',
                        background: 'var(--mp-glass-control, rgba(255,255,255,0.06))',
                        color: 'var(--muted)',
                        display: 'grid',
                        placeItems: 'center',
                        cursor: 'pointer',
                        flexShrink: 0,
                      }}
                    >
                      <RotateCcw size={12} />
                    </button>
                  )}
                </label>
              </div>
            </motion.div>
          </div>
        </section>

        {/* Custom Mode: Page & Card Shapes */}
        {editingMode === 'custom' && (
          <motion.section
            className="mp-appearance-section"
            {...dashSectionMotion(prefersReducedMotion, 0, true)}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
              <Shapes size={20} style={{ color: 'var(--brand-ink, #34D399)', flexShrink: 0 }} />
              <h2 className="mp-appearance-section-title" style={{ margin: 0 }}>
                شكل الصفحة والبطاقات
              </h2>
            </div>

            <div className="mp-appearance-shapes-grid">
              {customShapes.map((shape, idx) => {
                const isSelected = menuThemeShape === shape.id;
                const seasonalDecor =
                  shape.id === 'ramadan'
                    ? { left: '🏮', right: '🌙', badge: '✦' }
                    : shape.id === 'eid'
                    ? { left: '🎈', right: '🎉', badge: '🎊' }
                    : shape.id === 'newyear'
                    ? { left: '❄️', right: '🎆', badge: '✨' }
                    : null;

                return (
                  <motion.button
                    key={shape.id}
                    type="button"
                    onClick={() => handleSelectThemeShape(shape.id)}
                    className={`mp-appearance-shape-card ${isSelected ? 'selected' : ''}`}
                    {...dashCardMotion(prefersReducedMotion, idx, 1, true, 0.05)}
                  >
                    <div className={`mp-shape-preview mp-shape-preview-${shape.id}`}>
                      <div className="mp-shape-mini-banner">
                        {seasonalDecor && (
                          <div className="mp-shape-seasonal-icons" aria-hidden="true">
                            <span>{seasonalDecor.right}</span>
                            <span>{seasonalDecor.badge}</span>
                            <span>{seasonalDecor.left}</span>
                          </div>
                        )}
                      </div>
                      <div className="mp-shape-mini-row">
                        <div className="mp-shape-mini-avatar" />
                        <div className="mp-shape-preview-box">
                          <div className="mp-shape-preview-thumb" />
                          <div className="mp-shape-preview-meta">
                            <span className="mp-shape-preview-bar" />
                            <span className="mp-shape-preview-btn" />
                          </div>
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', gap: '6px' }}>
                      <b style={{ fontSize: '15px', color: isSelected ? 'var(--brand-ink, #34D399)' : 'var(--ink)' }}>
                        {shape.name}
                      </b>
                      {isSelected ? (
                        <span
                          style={{
                            fontSize: '12px',
                            fontWeight: 900,
                            color: 'var(--brand-ink, #34D399)',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          مفعّل ✓
                        </span>
                      ) : shape.badge ? (
                        <span
                          style={{
                            fontSize: '11.5px',
                            fontWeight: 800,
                            color: 'var(--brand-ink, #34D399)',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {shape.badge}
                        </span>
                      ) : null}
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </motion.section>
        )}
      </div>
    );
  }

  // Main Choose Appearance Landing View
  return (
    <div className="mp-appearance-page">
      {/* 1. Menu Display Mode (Light / Dark / Auto) */}
      {renderModeSwitcherBar()}

      {/* 2. Choose Appearance Mode (Ready-made Themes & Custom — Addons Card Style) */}
      <motion.section
        className="mp-appearance-section"
        {...dashSectionMotion(prefersReducedMotion, 0.08)}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', flexWrap: 'wrap', marginBottom: '14px' }}>
          <h2 className="mp-appearance-section-title" style={{ margin: 0 }}>
            اختر مظهر
          </h2>
        </div>

        <div className="mp-addons-grid">
          {READY_APPEARANCES.map((preset, idx) => {
            const isActive = menuThemeShape === preset.id;
            return (
              <motion.div
                key={preset.id}
                className={`mp-addon-square-card ${isActive ? 'is-enabled' : ''}`}
                {...dashCardMotion(prefersReducedMotion, idx, 1, false, 0.05)}
              >
                <div className="mp-addon-card-head">
                  <div className={`mp-addon-card-icon ${isActive ? 'is-enabled' : ''}`} aria-hidden="true">
                    <span>{preset.icon}</span>
                  </div>
                  <b className="mp-addon-card-title">{preset.title}</b>
                </div>

                <div className="mp-addon-card-body">
                  <p className="mp-addon-card-desc">{preset.desc}</p>
                  <div
                    className="mp-addon-card-meta"
                    style={{ color: isActive ? 'var(--brand)' : 'var(--muted)' }}
                  >
                    مظهر جاهز · {isActive ? `اللون: ${activeColorLabel}` : 'تعديل الألوان فقط'}
                  </div>
                </div>

                <div className="mp-addon-card-actions">
                  <button
                    type="button"
                    onClick={() => {
                      if (!isActive) {
                        handleSelectThemeShape(preset.id);
                      }
                    }}
                    aria-pressed={isActive}
                    className={`mp-addon-btn-toggle ${isActive ? 'is-start' : ''}`}
                    style={
                      !isActive
                        ? {
                            border: '1px solid var(--mp-glass-border)',
                            background: 'var(--mp-glass-control)',
                            color: 'var(--ink)',
                          }
                        : undefined
                    }
                  >
                    <span
                      className={`mp-addon-dot ${isActive ? 'is-on' : ''}`}
                      style={!isActive ? { background: 'var(--muted)' } : undefined}
                    />
                    <span>{isActive ? 'معيّن' : 'تعيين'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => openEditPage(preset.id)}
                    className="mp-addon-btn-edit"
                  >
                    <Edit size={12} />
                    <span>تعديل</span>
                  </button>
                </div>
              </motion.div>
            );
          })}

          {/* Custom Appearance */}
          <motion.div
            className={`mp-addon-square-card ${isCustomActive ? 'is-enabled' : ''}`}
            {...dashCardMotion(prefersReducedMotion, READY_APPEARANCES.length, 1, false, 0.05)}
          >
            <div className="mp-addon-card-head">
              <div className={`mp-addon-card-icon ${isCustomActive ? 'is-enabled' : ''}`} aria-hidden="true">
                <span>🎨</span>
              </div>
              <b className="mp-addon-card-title">مخصص</b>
            </div>

            <div className="mp-addon-card-body">
              <p className="mp-addon-card-desc">
                تحكم كامل بلون المنيو، شكل عرض المنتجات (4 أو 3 أو مربعين أو قائمة)، وشكل الصفحة والبطاقات.
              </p>
              <div
                className="mp-addon-card-meta"
                style={{ color: isCustomActive ? 'var(--brand)' : 'var(--muted)' }}
              >
                {activeLayoutObj?.title || 'شبكة'} · {activeCustomShapeObj?.name || 'عصري ناعم'}
              </div>
            </div>

            <div className="mp-addon-card-actions">
              <button
                type="button"
                onClick={() => {
                  if (!isCustomActive) {
                    handleActivateCustomAppearance();
                  }
                }}
                aria-pressed={isCustomActive}
                className={`mp-addon-btn-toggle ${isCustomActive ? 'is-start' : ''}`}
                style={
                  !isCustomActive
                    ? {
                        border: '1px solid var(--mp-glass-border)',
                        background: 'var(--mp-glass-control)',
                        color: 'var(--ink)',
                      }
                    : undefined
                }
              >
                <span
                  className={`mp-addon-dot ${isCustomActive ? 'is-on' : ''}`}
                  style={!isCustomActive ? { background: 'var(--muted)' } : undefined}
                />
                <span>{isCustomActive ? 'معيّن' : 'تعيين'}</span>
              </button>
              <button
                type="button"
                onClick={() => openEditPage('custom')}
                className="mp-addon-btn-edit"
              >
                <Edit size={12} />
                <span>تعديل</span>
              </button>
            </div>
          </motion.div>
        </div>
      </motion.section>
    </div>
  );
};
