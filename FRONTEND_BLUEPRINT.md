# IMMUNIS ACIN — Frontend Design Blueprint

> **Frontend master context file. Read alongside IMMUNIS_ACIN.md.**
> Contains design philosophy, color system, component architecture,
> page specifications, and implementation plan.

---

## Design Philosophy: "Calm Vigilance"

The feeling of a highly trained immune system at rest.
Quiet confidence. Serene until action needed, then precise and decisive.

**NOT:** Aggressive reds, neon, gaming aesthetic, generic dark AI, flat government software.
**IS:** Apple's design philosophy meets Bloomberg's information density.

## Color System (3 Modes)

| Token | Midnight | Twilight | Overcast |
|-------|----------|----------|----------|
| bg-primary | #0A0E1A | #1A1F2E | #F8FAFC |
| bg-secondary | #111827 | #242B3D | #FFFFFF |
| text-primary | #F9FAFB | #E8ECF4 | #0F172A |
| immune | #00E5A0 | #00E5A0 | #00C98A |
| threat | #FF4D6A | #FF4D6A | #E11D48 |
| warning | #FFAA33 | #FFAA33 | #D97706 |
| novel | #A78BFA | #A78BFA | #7C3AED |
| mesh | #38BDF8 | #38BDF8 | #0284C7 |

## Typography

- Display/Headings: Satoshi (700/600)
- Body: Inter (400/500) at 14px
- Code/Data: JetBrains Mono (400) at 13px
- Metrics: Inter tabular figures (600) at 32-48px

## Component Architecture

- 122 total component files
- 3 providers (Theme, Auth, WebSocket)
- 13 hooks
- 6 utility modules
- 19 common components
- 5 layout components
- 13 pages
- ~57 feature components across 12 categories

## Implementation Phases

| Phase | Files | Lines | Status |
|-------|-------|-------|--------|
| 1. Foundation (themes, utils) | 11 | ~2,740 | ✅ COMPLETE |
| 2. Providers + Hooks | 13 | ~900 | 🔲 NEXT |
| 3. Common Components | 19 | ~1,240 | 🔲 |
| 4. Layout + Router | 8 | ~540 | 🔲 |
| 5. Pages + Features | ~70 | ~5,500 | 🔲 |
| **Total** | **~122** | **~10,920** | |

## Key Design Decisions

1. **3-level navigation:** Sidebar → Tabs → Slide panels
2. **Command palette (Cmd+K):** Power user quick access
3. **Density modes:** Compact / Comfortable / Spacious
4. **Cinematic visualization:** Three.js WebGL for Track 3 showpiece
5. **4 test modes:** Manual, Automated Demo, Live Integration, Stress Test
6. **6 audience levels:** SOC, IR, CISO, IT, Finance, Auditor
7. **Framer Motion:** All animations via reusable variants
8. **prefers-reduced-motion:** Respected throughout

---

*Created: Session 7b, May 8, 2026*
