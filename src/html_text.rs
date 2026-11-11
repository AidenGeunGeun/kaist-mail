//! Dooray's HTML message bodies as plain text for reading.

use html2text::render::RichAnnotation;

use crate::error::AppError;

/// Wide enough that prose is never wrapped. Raw mode puts each table cell on
/// its own line, so layout tables cannot pad lines with spaces.
const WIDTH: usize = 2000;

/// Renders `html` as text: quotes keep their `> ` prefix, links read
/// `text <url>`, images `[alt]`, and runs of blank lines collapse.
pub fn to_text(html: &str) -> Result<String, AppError> {
    let lines = html2text::config::rich()
        .raw_mode(true)
        .no_link_wrapping()
        .allow_width_overflow()
        .lines_from_read(html.as_bytes(), WIDTH)
        .map_err(|error| AppError::shape(format!("could not render the message HTML: {error}")))?;
    let mut text = String::new();
    for line in &lines {
        let mut rendered = String::new();
        let mut span = Span::default();
        for segment in line.tagged_strings() {
            let mut next = Span::default();
            for annotation in &segment.tag {
                match annotation {
                    RichAnnotation::Link(url) => next.link = Some(url),
                    RichAnnotation::Image(_) => next.image = true,
                    _ => {}
                }
            }
            if (next.link, next.image) != (span.link, span.image) {
                span.close(&mut rendered);
                span = Span {
                    start: rendered.len(),
                    ..next
                };
            }
            rendered.push_str(&segment.s);
        }
        span.close(&mut rendered);
        let rendered = rendered.trim_end();
        if rendered.is_empty() && (text.is_empty() || text.ends_with("\n\n")) {
            continue;
        }
        text.push_str(rendered);
        text.push('\n');
    }
    Ok(text.trim_end().to_owned())
}

/// A run of segments with the same link and image annotations, starting at
/// byte `start` of the line.
#[derive(Default)]
struct Span<'a> {
    start: usize,
    link: Option<&'a str>,
    image: bool,
}

impl Span<'_> {
    fn close(&self, rendered: &mut String) {
        let text = rendered[self.start..].trim().to_owned();
        if self.image {
            rendered.insert(self.start, '[');
            rendered.push(']');
        }
        let Some(url) = self.link else { return };
        if text != url && Some(text.as_str()) != url.strip_prefix("mailto:") {
            rendered.push_str(" <");
            rendered.push_str(url);
            rendered.push('>');
        }
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
        ] {
            assert_eq!(to_text(html).unwrap(), text, "{html}");
        }
    }
}
