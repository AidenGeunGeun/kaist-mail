//! Dooray's HTML message bodies as plain text for reading.

use html2text::render::{TaggedLine, TextDecorator};

use crate::error::AppError;

/// Wide enough that prose is never wrapped. Raw mode puts each table cell on
/// its own line, so layout tables cannot pad lines with spaces.
const WIDTH: usize = 2000;

/// Renders `html` as text: quotes keep their `> ` prefix, links read
/// `text <url>`, images `[alt]`, and runs of blank lines collapse.
pub fn to_text(html: &str) -> Result<String, AppError> {
    let lines = html2text::config::with_decorator(Decorator)
        .raw_mode(true)
        .no_link_wrapping()
        .allow_width_overflow()
        .lines_from_read(html.as_bytes(), WIDTH)
        .map_err(|error| AppError::shape(format!("could not render the message HTML: {error}")))?;
    let mut text = String::new();
    for line in &lines {
        let mut rendered = String::new();
        let mut link: Option<&str> = None;
        let mut start = 0;
        for segment in line.tagged_strings() {
            let url = segment.tag.iter().find_map(Option::as_deref);
            if url != link {
                close_link(&mut rendered, start, link);
                link = url;
                start = rendered.len();
            }
            rendered.push_str(&segment.s);
        }
        close_link(&mut rendered, start, link);
        let rendered = rendered.trim_end();
        if rendered.is_empty() && (text.is_empty() || text.ends_with("\n\n")) {
            continue;
        }
        text.push_str(rendered);
        text.push('\n');
    }
    Ok(text.trim_end().to_owned())
}

/// Appends ` <url>` to the link text that starts at byte `start`, unless the
/// text already shows the address.
fn close_link(rendered: &mut String, start: usize, url: Option<&str>) {
    let Some(url) = url else { return };
    let text = rendered[start..].trim();
    if text != url && Some(text) != url.strip_prefix("mailto:") {
        rendered.push_str(" <");
        rendered.push_str(url);
        rendered.push('>');
    }
}

/// Annotates each span with the URL of the link it is in, and renders
/// images as `[alt]`, list items and quotes with their markers.
#[derive(Clone, Copy)]
struct Decorator;

impl TextDecorator for Decorator {
    type Annotation = Option<String>;

    fn decorate_link_start(&mut self, url: &str) -> (String, Self::Annotation) {
        (String::new(), Some(url.to_owned()))
    }
    fn decorate_link_end(&mut self) -> String {
        String::new()
    }
    fn decorate_em_start(&self) -> (String, Self::Annotation) {
        (String::new(), None)
    }
    fn decorate_em_end(&self) -> String {
        String::new()
    }
    fn decorate_strong_start(&self) -> (String, Self::Annotation) {
        (String::new(), None)
    }
    fn decorate_strong_end(&self) -> String {
        String::new()
    }
    fn decorate_strikeout_start(&self) -> (String, Self::Annotation) {
        (String::new(), None)
    }
    fn decorate_strikeout_end(&self) -> String {
        String::new()
    }
    fn decorate_code_start(&self) -> (String, Self::Annotation) {
        (String::new(), None)
    }
    fn decorate_code_end(&self) -> String {
        String::new()
    }
    fn decorate_preformat_first(&self) -> Self::Annotation {
        None
    }
    fn decorate_preformat_cont(&self) -> Self::Annotation {
        None
    }
    fn decorate_image(&mut self, _src: &str, title: &str) -> (String, Self::Annotation) {
        let alt = title.trim();
        let shown = if alt.is_empty() {
            String::new()
        } else {
            format!("[{alt}]")
        };
        (shown, None)
    }
    fn header_prefix(&self, level: usize) -> String {
        "#".repeat(level) + " "
    }
    fn quote_prefix(&self) -> String {
        "> ".to_owned()
    }
    fn unordered_item_prefix(&self) -> String {
        "* ".to_owned()
    }
    fn ordered_item_prefix(&self, i: i64) -> String {
        format!("{i}. ")
    }
    fn make_subblock_decorator(&self) -> Self {
        *self
    }
    fn finalise(&mut self, _urls: Vec<String>) -> Vec<TaggedLine<Self::Annotation>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::to_text;

    #[test]
    fn an_image_or_link_may_follow_any_span_on_a_line() {
        for (html, text) in [
            (r#"<p><img alt="가" src="x"> suffix</p>"#, "[가] suffix"),
            (
                r#"<p><a href="https://a.test">A</a><img alt="그림" src="x"> 끝</p>"#,
                "A <https://a.test>[그림] 끝",
            ),
            (
                r#"<p>앞 <img alt="그림" src="x"><a href="https://a.test">링크</a></p>"#,
                "앞 [그림]링크 <https://a.test>",
            ),
            (
                r#"<p><img alt="가" src="x"><img alt="나" src="x"></p>"#,
                "[가][나]",
            ),
        ] {
            assert_eq!(to_text(html).unwrap(), text, "{html}");
        }
    }
}
