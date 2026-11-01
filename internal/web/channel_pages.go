package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/render"
)

// Canaux de notification (T15, ADR 0046) : liste, création, modification, essai et
// suppression. Un secret n'est jamais réaffiché : le champ vide garde le secret existant.

type channelRow struct {
	notify.Channel
	KindKey    string
	Href       string
	TestAction string
	DeleteHref string
	Target     string // destinataires, URL ou salon (jamais un secret)
	Success    *stamp
	Failure    *stamp
}

type testResult struct {
	Name     string
	OK       bool
	ErrorKey string
}

type channelsView struct {
	render.Page
	Base     string
	Rows     []channelRow
	NewHref  string
	FlashKey string
	Test     *testResult
	Max      int
}

func channelTarget(c notify.Channel) string {
	switch c.Kind {
	case notify.KindEmail:
		return strings.Join(c.Settings.Recipients, ", ")
	case notify.KindWebhook:
		return c.Settings.URL
	case notify.KindMatrix:
		return c.Settings.Room
	}
	return ""
}

func (id *identity) renderChannels(w http.ResponseWriter, r *http.Request, test *testResult) {
	acc := access(r)
	cs, err := id.Notify.Channels(r.Context(), acc.Org)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base := orgBase(acc)
	view := &channelsView{Page: render.Page{TitleKey: "channels.title", Nav: orgNav(acc, "channels")}, Base: base,
		NewHref: base + "/channels/new", FlashKey: flashKey(r), Test: test, Max: notify.MaxChannels}
	for _, c := range cs {
		h := base + "/channels/" + c.ID.String()
		view.Rows = append(view.Rows, channelRow{Channel: c, KindKey: "channel_kind." + string(c.Kind), Href: h,
			TestAction: h + "/test", DeleteHref: h + "/delete", Target: channelTarget(c), Success: stampOf(c.LastSuccessAt),
			Failure: stampOf(c.LastFailureAt)})
	}
	id.rd.Render(w, r, http.StatusOK, "org/channels", view)
}

func (id *identity) channels(w http.ResponseWriter, r *http.Request) { id.renderChannels(w, r, nil) }

type channelForm struct {
	Name       string
	Kind       string
	Enabled    bool
	Recipients string
	URL        string
	Homeserver string
	Room       string
}

type channelView struct {
	render.Page
	Base      string
	Action    string
	Cancel    string
	Editing   bool
	HasSecret bool
	Form      channelForm
	Kinds     []option
	Error     formError
}

func (id *identity) renderChannelForm(w http.ResponseWriter, r *http.Request, status int, editID uuid.UUID, hasSecret bool,
	form channelForm, fe formError) {
	acc := access(r)
	base := orgBase(acc)
	view := &channelView{Page: render.Page{TitleKey: "channel_form.title_new", Nav: orgNav(acc, "channels"), Failed: status >= 400},
		Base: base, Action: base + "/channels", Cancel: base + "/channels", Form: form, Error: fe, HasSecret: hasSecret}
	if editID != uuid.Nil {
		view.Editing, view.Action = true, base+"/channels/"+editID.String()
		view.Page.TitleKey, view.Page.TitleArgs = "channel_form.title_edit", map[string]any{"Name": form.Name}
	}
	for _, k := range notify.Kinds() {
		view.Kinds = append(view.Kinds, option{Value: string(k), LabelKey: "channel_kind." + string(k), Selected: string(k) == form.Kind})
	}
	id.rd.Render(w, r, status, "org/channel", view)
}

func (id *identity) newChannel(w http.ResponseWriter, r *http.Request) {
	id.renderChannelForm(w, r, http.StatusOK, uuid.Nil, false, channelForm{Kind: string(notify.KindEmail), Enabled: true}, formError{})
}

func readChannelForm(r *http.Request) (channelForm, notify.Input) {
	f := channelForm{Name: r.PostFormValue("name"), Kind: r.PostFormValue("kind"), Enabled: r.PostFormValue("enabled") == "1",
		Recipients: r.PostFormValue("recipients"), URL: r.PostFormValue("url"), Homeserver: r.PostFormValue("homeserver"),
		Room: r.PostFormValue("room")}
	in := notify.Input{Name: f.Name, Kind: notify.Kind(f.Kind), Enabled: f.Enabled, Secret: r.PostFormValue("secret"),
		Settings: notify.Settings{URL: f.URL, Homeserver: f.Homeserver, Room: f.Room}}
	for _, part := range strings.FieldsFunc(f.Recipients, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		if p := strings.TrimSpace(part); p != "" {
			in.Settings.Recipients = append(in.Settings.Recipients, p)
		}
	}
	return f, in
}

func (id *identity) saveChannel(w http.ResponseWriter, r *http.Request, editID uuid.UUID, hasSecret bool) {
	if !id.parseForm(w, r) {
		return
	}
	acc := access(r)
	form, in := readChannelForm(r)
	var err error
	if editID == uuid.Nil {
		_, err = id.Notify.CreateChannel(r.Context(), acc.Org, id.actor(r), in)
	} else {
		_, err = id.Notify.UpdateChannel(r.Context(), acc.Org, id.actor(r), editID, in)
	}
	switch {
	case errors.Is(err, notify.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	case err != nil:
		if fe, ok := validationOf(err); ok {
			id.renderChannelForm(w, r, http.StatusUnprocessableEntity, editID, hasSecret, form, fe)
			return
		}
		id.serverError(w, r, err)
	default:
		redirectDone(w, r, orgBase(acc)+"/channels", "channel_saved")
	}
}

func (id *identity) createChannel(w http.ResponseWriter, r *http.Request) {
	id.saveChannel(w, r, uuid.Nil, false)
}

func (id *identity) channelFromPath(w http.ResponseWriter, r *http.Request) (notify.Channel, bool) {
	cid, err := uuid.Parse(chi.URLParam(r, "channelID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return notify.Channel{}, false
	}
	c, err := id.Notify.Channel(r.Context(), access(r).Org, cid)
	if errors.Is(err, notify.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return c, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return c, false
	}
	return c, true
}

func (id *identity) channelPage(w http.ResponseWriter, r *http.Request) {
	c, ok := id.channelFromPath(w, r)
	if !ok {
		return
	}
	form := channelForm{Name: c.Name, Kind: string(c.Kind), Enabled: c.Enabled, Recipients: strings.Join(c.Settings.Recipients, "\n"),
		URL: c.Settings.URL, Homeserver: c.Settings.Homeserver, Room: c.Settings.Room}
	id.renderChannelForm(w, r, http.StatusOK, c.ID, c.HasSecret, form, formError{})
}

func (id *identity) updateChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := id.channelFromPath(w, r)
	if !ok {
		return
	}
	id.saveChannel(w, r, c.ID, c.HasSecret)
}

// testChannel envoie un message de test et affiche son issue sur la liste des canaux.
func (id *identity) testChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := id.channelFromPath(w, r)
	if !ok {
		return
	}
	sendErr, err := id.Notify.TestChannel(r.Context(), access(r).Org, id.actor(r), c.ID)
	switch {
	case errors.Is(err, notify.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
		return
	case err != nil:
		id.serverError(w, r, err)
		return
	}
	res := &testResult{Name: c.Name, OK: sendErr == nil}
	if sendErr != nil {
		res.ErrorKey = notify.ErrorKey(sendErr)
	}
	id.renderChannels(w, r, res)
}

func (id *identity) confirmDeleteChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := id.channelFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	id.confirm(w, r, confirmation{nav: orgNav(acc, "channels"), heading: "confirm.channel_heading", text: "confirm.channel_text",
		submit: "confirm.channel_submit", args: map[string]any{"Name": c.Name, "Count": c.Policies}, cancel: orgBase(acc) + "/channels"})
}

func (id *identity) deleteChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := id.channelFromPath(w, r)
	if !ok {
		return
	}
	acc := access(r)
	err := id.Notify.DeleteChannel(r.Context(), acc.Org, id.actor(r), c.ID)
	switch {
	case errors.Is(err, notify.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
	case err != nil:
		id.serverError(w, r, err)
	default:
		redirectDone(w, r, orgBase(acc)+"/channels", "channel_deleted")
	}
}
