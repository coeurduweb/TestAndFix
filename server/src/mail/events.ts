// In-process event bus between the receivers / analyzer and the SSE streams of the interface.
import { EventEmitter } from 'node:events';

// ownerId: notebook of the message; a stream only forwards the events of its own notebook.
export type MailEvent =
  | { type: 'message'; addressId: string; messageId: string; ownerId: string | null; data: unknown }
  | { type: 'progress'; addressId: string; messageId: string; ownerId: string | null; data: { step: string; label: string; state: 'start' | 'done' | 'skipped' | 'error'; detail?: string } }
  | { type: 'report'; addressId: string; messageId: string; ownerId: string | null; data: unknown }
  | { type: 'error'; addressId: string; messageId: string; ownerId: string | null; data: { error: string } };

class MailBus extends EventEmitter {
  publish(ev: MailEvent) {
    this.emit(`address:${ev.addressId}`, ev);
    this.emit(`message:${ev.messageId}`, ev);
    this.emit('any', ev);
  }
}

export const mailBus = new MailBus();
mailBus.setMaxListeners(0);
