// An URL that wraps after "/", "?", "&" and "=" rather than in the middle of a word.
import { Fragment } from 'react';

export function Url({ href }: { href: string }) {
  // never right after the scheme ("https://")
  const parts = href.split(/(?<=[^/:]\/|[?&=])/);
  return (
    <>
      {parts.map((p, i) => (
        <Fragment key={i}>
          {p}
          {i < parts.length - 1 && <wbr />}
        </Fragment>
      ))}
    </>
  );
}
