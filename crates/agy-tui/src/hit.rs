//! Mouse hit-test regions, pointer shapes, and render frame context.

use alloc::vec::Vec;

use crate::layout::Rect;
use crate::surface::{BorderSet, Surface};

/// Desired terminal mouse cursor shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PointerShape {
    #[default]
    Default,
    Pointer,
    ColResize,
    RowResize,
}

impl PointerShape {
    #[must_use]
    pub const fn osc22_name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Pointer => "pointer",
            Self::ColResize => "col-resize",
            Self::RowResize => "row-resize",
        }
    }
}

/// Application-defined interactive target identifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HitId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HitRegion {
    id: HitId,
    rect: Rect,
    pointer: PointerShape,
}

/// Z-ordered stack of interactive screen rectangles for a rendered frame.
#[derive(Clone, Debug, Default)]
pub struct HitMap {
    regions: Vec<HitRegion>,
}

impl HitMap {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.regions.clear();
    }

    pub fn push(&mut self, id: HitId, rect: Rect, pointer: PointerShape) {
        if !rect.is_empty() {
            self.regions.push(HitRegion { id, rect, pointer });
        }
    }

    #[must_use]
    pub fn hit_test(&self, x: u16, y: u16) -> Option<(HitId, PointerShape)> {
        for region in self.regions.iter().rev() {
            if region.rect.contains(x, y) {
                return Some((region.id, region.pointer));
            }
        }
        None
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

/// Single-frame drawing and hit-registration context.
pub struct Frame<'a> {
    pub surface: &'a mut Surface,
    pub hits: &'a mut HitMap,
    pub ascii: bool,
}

impl<'a> Frame<'a> {
    #[must_use]
    pub fn new(surface: &'a mut Surface, hits: &'a mut HitMap, ascii: bool) -> Self {
        Self {
            surface,
            hits,
            ascii,
        }
    }

    #[must_use]
    pub fn size(&self) -> Rect {
        Rect::new(0, 0, self.surface.width(), self.surface.height())
    }

    pub fn hit(&mut self, id: HitId, rect: Rect, pointer: PointerShape) {
        self.hits.push(id, rect, pointer);
    }

    #[must_use]
    pub fn borders(&self) -> BorderSet {
        if self.ascii {
            BorderSet::ASCII
        } else {
            BorderSet::ROUNDED
        }
    }
}
