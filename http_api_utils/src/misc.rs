use parse_display::Display;

#[derive(Clone, Copy, Debug, Display)]
#[display(style = "lowercase")]
pub enum Direction {
    Request,
    Response,
}
